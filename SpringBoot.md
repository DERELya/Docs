# **SPRING BOOT**

# **Основы**

## 1.Терминология

В Spring нам не нужно вручную создавать объекты при помощи new, всем управляет IoC-контейнер

### Ядро и управление объектами

* Inversion of Control(Ioc) инверсия управления. Принцип при котором контроль за жизненным циклом передается фреймворку.
* Dependency Injection(DI) внедрение зависимостей.
* Bean это просто объект который создан, настроен и управляется Spring фреймворком. По сути это обычный Java класс, но с
  пропиской внутри фреймворка.
* Application Context главный интерфейс в Spring представляющий собой тот самый IoC контейнер, он знает какие бины есть,
  как они связаны и как их выдать.
*

### Аннотации конфигурации

Для того чтобы Spring понял что делать с нашими классами есть аннотации

* `@Component` базовая аннотация при помощи которой Spring сделает из нашего класса бин.
* `@Service` создает сервис в котором описана бизнес логика.
* `@Repository` создает репозиторий для работы с базой данных.
* `@Controller` создает контроллер который обрабатывает Http запросы.
* `@Configuration` помечает класс внутри которого описаны правила для бинов.
* `@Bean` ставится над методом внутри @Configuration, результат выполнения этого метода станет бином.

### Spring MVC(WEB)

* DispatcherServlet Принимает все запросы и решает какому контроллеру их передать.
* Controller класс, который обрабатывает Http запросы, принимает его и возвращает ответ.
* DTO(Data transfer Object) Объект, который используется только для передачи данных(мы можем передать пользователю только
нужные поля, например Id ему не нужен и в Dto его не будет).
* Payload тело запроса или полезная нагрузка.

## 2.Архитектура

Есть 4 слоя приложения на Spring boot

1. Уровень представления.
2. Бизнес-логика.
3. Уровень персистентности.
4. Уровень базы данных.

![img_1.png](img_1.png)

* Уровень представления это первый уровень на котором приложение получает запрос и проводит аутентификацию пользователя(кто зашел).
  
В Spring это: @Controller и @RestController.
* Бизнес-логика здесь происходят вся основная логика, валидация и авторизация(проверка прав доступа).
  
В Spring это: @Service.
* Уровень персистентности или слой доступа к данным это логика хранения данных, этот слой не знает как проходят расчеты, он просто сохраняет и достает данные из бд.
  
В Spring это: @Repository.
* Уровень базы данных сама СУБД(PostgreSQL, MySQL) место где физически хранится информация.

### Пример регистрации пользователя
1. Пользователь отправляет форму со своим логином и паролем, мы проверяем что email это email (это делает контроллер).
2. Дальше мы проверяем что имя не занято, шифруем пароль и вызываем метод репозитория (это делает сервис).
3. В репозитории был вызван метод `save()` и формуриуется SQL запрос, а после отправляется в БД(это делает репозиторий).
4. Дальше СУБД записывает новую информацию.

Подобная архитектура гибкая, так как если бы решим изменить БД нам не нужно будет трогать сервисы и контроллеры, и также если мы решим изменить логику обработки мы меняем только нужный нам слой.
## 3.Почему Spring

### 1. Экосистема
Spring это огромный конструктор, не нужно искать сторонние решения.
* Spring Security — готовая защита (логин, роли, шифрование).
* Spring Data — упрощает работу с БД.
* Spring Cloud — для создания сложных распределенных систем (микросервисов).
### 2. Spring Boot(скорость и удобство)
* Автоконфигурация:Spring Boot сам понимает, что если в проекте есть библиотека для работы с базой данных, значит, нужно автоматически создать подключение к ней.
* Встроенный сервер:не нужно устанавливать и настраивать Tomcat отдельно.
### 3. Тестируемость
Поскольку зависимости (например, репозиторий) «внедряются» в сервис, можно легко подменить настоящий репозиторий «фейковым» (моком) во время тестов, не запуская настоящую базу данных.
## 4.Конфигурация
### 1. Конфигурация через Java классы
Можно создать специальный класс конфигурации `@Configuration` для использования библиотек например (Jackson)
```java
@Configuration // Говорим Spring: "Тут лежат рецепты для создания объектов"
public class AppConfig {

    @Bean // Результат этого метода станет бином и попадет в IoC-контейнер
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(); 
    }
}
```
### 2. Разница между @Component и @Bean
* Первое ставится над классом, Bean над методом в `@Configuration`
* При `@Component` Spring сам создает при сканировании пакетов, а `@Bean` сами должны создать в теле метода
* `@Component` используется для своих классов, а `@Bean` для сторонних библиотек и сложной логики создания

### 3.Файлы свойств
Spring Boot позволяет выносить настройки во внешние файлы.
* application.properties: простой формат ключ=значение.
* application.yml: древовидный формат, более читаемый для сложных настроек.
### 4. Решение конфликтов
Иногда бывает так, что у тебя есть один интерфейс (например, `Sender`), но две реализации: `EmailSender` и `SmsSender`. Оба помечены как `@Service`.
Когда ты напишешь `@Autowired private Sender sender;`, Spring запаникует: "Я не знаю, какой из двух выбрать!".

Как это решить:
`@Primary`: Поставь её над одним из классов. Spring будет считать его "главным" по умолчанию.

@Qualifier("smsSender"): Укажи конкретное имя бина прямо в месте внедрения, чтобы Spring точно знал, что ты хочешь именно SMS.
## 5.Внедрение зависимостей
Это одно из преимуществ Spring когда не класс ищет нужный ему инструмент, а Spring приносит ему его сам

Пример:

Пишем сервис для отправки уведомлений 

Без DI
```java
public class NotificationService {
    private EmailSender sender = new EmailSender(); // Жесткая связь
}
```
С DI
```java
@Service
public class NotificationService {
    private final MessageSender sender;

    @Autowired // Spring сам найдет подходящий бин и "вставит" его сюда
    public NotificationService(MessageSender sender) {
        this.sender = sender;
    }
}
```

### Способы внедрения 
1. Через конструктор (рекомендуемый)

* Объект нельзя создать без зависимости 
* Поля можно пометить как final
2. Через сеттер
* Используется редко когда зависимость может меняться или необязательная
3. Через поле @Autowired
* Трудно тестировать так как нельзя просто передать «заглушку» в конструктор
* Скрывает зависимости

### Автосвязывание
Когда ставим аннотацию @Autowired Spring ищет подходящий бин
* Сначала ищет класс или интерфейс того же типа 
* Если типов несколько ищет тот, чье имя совпадает с именем переменной
## 6.Spring Ioc
**Инверсия управления** — это концепция, при которой ты передаешь контроль над созданием объектов фреймворку.

Раньше (без IoC): Ты сам писал new MyService(), сам следил, чтобы сначала создалась база данных, а потом сервис. Ты был «главным».

Со Spring (IoC): Ты просто помечаешь классы аннотациями, а Spring сам решает, в каком порядке их создавать, как связывать и когда удалять. Теперь «главный» — Spring.
### Как работает IoC-контейнер
1. Чтение метаданных: Spring сканирует проект (аннотации `@Service`,`@Component`) или читает конфигурационный файл Java(`@Configuration`)
2. Создание бинов
3. Внедрение зависимостей: контейнер связывает объекты между собой 

### Иерархия контейнеров
В Spring есть два основных интерфейса, которые представляют IoC-контейнер:

* BeanFactory: Самый простой контейнер. Он просто хранит бины и отдает их. Используется редко, в основном на мобильных устройствах или в очень легких приложениях.

* ApplicationContext: «Старший брат» BeanFactory. Именно его мы используем в 99% случаев.
Он умеет всё, что BeanFactory + добавляет поддержку событий (Events), интернационализацию (перевод текстов) и тесную интеграцию с веб-слоем.
### Жизненный цикл бинов в IoC
1. Создание: вызывается конструктор
2. Наполнение: внедряются зависимости
3. Инициализация: `@PreConstructor` выполняются стартовые методы
4. Работа: Бин используется
5. Уничтожение: `@PreDestroy` перед завершением приложения
## 7.Spring AOP
Spring AOP это аспектно-ориентированное программирование, AOP помогает избавиться от дублирования кода, который не относится к бизнес-логике

### Основные понятия 
* Aspect (Аспект): Это класс, в котором описана «сквозная» логика (например, логирование). Это «ЧТО» мы делаем.
* Advice (Совет): Конкретное действие, выполняемое аспектом. Оно определяет, когда запустить код (до метода, после или вместо).
* Join Point (Точка соединения): Любая точка в программе, где можно применить аспект (в Spring это всегда вызов метода).
* Pointcut (Срез): Это набор правил (фильтр), который определяет, к каким именно методам нужно применить аспект. Например: «ко всем методам в пакете service».
* Target Object (Целевой объект): Объект, к методам которого применяется аспект.
### Типы Advice
* @Before: Код выполнится до основного метода.
* @After: Код выполнится после метода (неважно, была ошибка или нет).
* @AfterReturning: Сработает только если метод завершился успешно.
* @AfterThrowing: Сработает только если метод выбросил исключение.
* @Around: Самый мощный. Он полностью оборачивает метод. Ты сам решаешь, когда вызвать основной код и вызывать ли его вообще (идеально для замера времени выполнения).
### Как это работает
Когда вызывается метод сервиса, Spring подсовывает прокси-объект и он сначала выполняет логику аспекта, а потом внутри себя вызывает реальный метод 

```java
@Aspect
@Component
public class LoggingAspect {

    // Pointcut: следим за всеми методами в UserService
    @Before("execution(* com.example.service.UserService.*(..))")
    public void logBefore() {
        System.out.println("--- Аспект: Проверка прав пользователя перед вызовом метода ---");
    }

    // Around: замеряем время работы любого метода с аннотацией @Timed
    @Around("@annotation(Timed)")
    public Object measureTime(ProceedingJoinPoint joinPoint) throws Throwable {
        long start = System.currentTimeMillis();
        
        Object result = joinPoint.proceed(); // Вызов самого метода
      
        long executionTime = System.currentTimeMillis() - start;
        System.out.println(joinPoint.getSignature() + " выполнен за " + executionTime + "мс");
        return result;
    }
}
```
## 8.Spring MVC
Spring MVC(Model-View-Controller) это модуль Spring который позволяет создавать веб-приложения. Он построен вокруг главного компонента DispatcherServlet, который распределяет запросы между контроллерами

### 1. Главные компоненты

* DispatcherServlet все запросы попадают к нему и после он решает к какому контроллеру отдать его.
* Handle Mapping помогает какой именно метод контроллера обрабатывает соответствующий URL  
* Controller сама логика обработки запроса
* ModelAndView контейнер с информацией какой View показать пользователю 
* View Resolver ищет нужный файл .html, .jsp в папке resource

### 2. Жизненный цикл запроса
1. Запрос приходит на DispatcherServlet
2. После он обращается к HandleMapping кто отвечает за этот запрос(/users)
3. Запрос передается контроллеру, он выполняет логику и возвращает ответ (всех пользователей из бд)
4. Выбор ответа в RESTApi(объект в виде DTO, который после будет JSON), в ClassicMVC(контроллер возвращает имя страницы и ViewResolver подгружает этот файл)
5. Ответ в виде JSON или страницы

### 3. Ключевые аннотации
* @Controller вернет страницу
* @RestController вернет JSON
* @RequestMapping задает базовый путь для контроллера(/user)
Извлечение данных:
* @PathVariable берет данные из пути (/user/{id}) 
* @RequestParam из строки запроса (?name=Ivan)
* @RequestBody превращает входящий JSON в объект(DTO)


```java
@RestController // Работаем в режиме API (возвращаем JSON)
@RequestMapping("/user")
public class UserController {

  private final UserService userService; 

  // Единственный конструктор — Spring внедрит зависимость автоматически
  public UserController(UserService userService) {
    this.userService = userService;
  }

    // GET запрос: http://localhost:8080/user/5
    @GetMapping("/{id}")
    public UserDto getUser(@PathVariable Long id) {
        return userService.getById(id);
    }

    // POST запрос: отправляем JSON в теле запроса
    @PostMapping
    public ResponseEntity<String> createUser(@RequestBody UserDto dto) {
        userService.save(dto);
        return ResponseEntity.ok("Пользователь создан");
    }
}
```
## 9.Аннотации
Аннотации в Spring — это способ конфигурации приложения без использования. Они помечают классы, методы или поля, давая инструкции IoC-контейнеру.

### 1. Стереотипные аннотации (Component Scanning)

   Они помечают классы, которые Spring должен превратить в Бины. По сути, все они — производные от @Component.
* @Component — базовая аннотация. Используется, когда класс не подходит под роль сервиса или контроллера (например, вспомогательные утилиты).
* @Service — помечает бизнес-логику.
* @Repository — слой доступа к данным. Она также включает автоматический перевод исключений базы данных в понятные Spring-исключения.
* @Controller — для веб-контроллеров (возвращают страницы).
* @RestController — для API. Это комбинация @Controller + @ResponseBody. Возвращает JSON.

### 2. Аннотации внедрения (Dependency Injection)
* @Autowired — главная аннотация для внедрения зависимостей. Лучше всего ставить её над конструктором.
* @Qualifier — используется вместе с @Autowired, когда нужно уточнить имя конкретного бина (если их несколько одного типа).
* @Primary — помечает бин, который должен быть выбран по умолчанию при конфликте типов.
* @Value — внедряет значения из application.properties (например, ${server.port}).

### 3. Аннотации конфигурации
* @Configuration — говорит Spring, что класс является источником настроек.
* @Bean — ставится над методом внутри @Configuration. Spring вызовет метод и зарегистрирует возвращаемый объект как бин.
* @ComponentScan — указывает пакеты, которые нужно сканировать на наличие компонентов (в Spring Boot обычно не нужна, так как работает автоматически).

### 4. Жизненный цикл (Bean Lifecycle)
* @PostConstruct — помечает метод, который выполнится сразу после того, как бин будет создан и зависимости будут внедрены. Удобно для начальной настройки.
* @PreDestroy — метод выполнится перед тем, как контейнер удалит бин (например, для закрытия сетевых соединений).

### 5. Spring MVC (Web) аннотации
* @RequestMapping — базовый путь запроса.
* @GetMapping, @PostMapping, @PutMapping, @DeleteMapping — сокращения для конкретных типов HTTP-запросов.
* @RequestBody — превращает входящий JSON в Java-объект.
* @PathVariable — достает переменную из пути (напр. /users/{id}).
* @RequestParam — достает параметр из строки (напр. ?name=Ivan).

## 10. Spring bean
Bean это объект, который создается, собирается и управляется контейнером Spring IoC. Bean содержит информацию, называемую метаданные конфигурации для того чтобы контейнер понимал как создать bean, его жизненный цикл и зависимости

Свойства:
* class указывает класс компонента который будет использоваться для создания бина
* name определяет идентификатор компонента
* scope определяет видимость объектов
* constructor-arg используется для внедрения зависимостей
* properties используется для внедрения зависимостей
* autowiring mode используется для внедрения зависимостей
* lazy-initialization mode говорит контейнеру создавать экземпляр компонента при первом запросе, а не при запуске.
* initialization method функция, которая будет вызываться сразу после того, как контейнер установит все необходимые свойства объекта.
* destruction method функция, которая будет использоваться при уничтожении контейнера, содержащего компонент.

### Область видимости
* Singleton (по умолчанию)Один экземпляр на всё приложение
* Prototype новый экземпляр создается каждый раз, когда его запрашивают (через @Autowired или context.getBean()). Метод @PreDestroy вызываться не будет.
* Request один экземпляр на каждый HTTP-запрос (только для веб-приложений).
* Session один экземпляр на каждую пользовательскую сессию.
* Global-session ограничивает область действия определения бина глобальной HTTP-сессией. Действительно только в контексте веб-ориентированного Spring ApplicationContext.

### Жизненный цикл
1. Инстанцирование: Spring вызывает конструктор класса.
2. Наполнение свойствами (DI): Spring внедряет зависимости в поля или через сеттеры.
3. Aware-интерфейсы: Если бин реализует спец. интерфейсы (например, BeanNameAware), Spring передает ему служебную информацию (имя бина и т.д.).
4. Инициализация:
   * Срабатывает метод с аннотацией @PostConstruct.
   * Если бин реализует InitializingBean, вызывается метод afterPropertiesSet().
5. Готовность: Бин готов к работе.
6. Уничтожение: Перед закрытием контекста срабатывает метод с аннотацией @PreDestroy.

### Как создать Bean
1. Автоматически (@Component): Spring сам находит класс и делает из него бин.
2. Вручную (@Bean): В классе @Configuration. Используется для сторонних библиотек.
3. XML: (Устарело) Через тег <bean>.

```java
@Component
@Scope("singleton") // Можно не писать, это по умолчанию
public class MyService {

    public MyService() {
        System.out.println("1. Шаг: Вызван конструктор");
    }

    @PostConstruct
    public void init() {
        System.out.println("2. Шаг: Бин готов, зависимости внедрены. Делаем донастройку.");
    }

    @PreDestroy
    public void cleanup() {
        System.out.println("3. Шаг: Приложение закрывается, освобождаем ресурсы.");
    }
}
```
# **Spring security**

## 1.Аутентификация
В Spring security все строится на цепочке фильтров(Filter Chain). Когда приходит запрос он не сразу попадает в контроллер
Аутентификация отвечает на вопрос "Кто ты?".
### 1. Как работает аутентификация
1. Filter перехватывает запрос и достает из него логин/пароль
2. AuthenticationManager Главный координатор. Он говорит: «У меня есть логин и пароль, кто может их проверить?».
3. AuthenticationProvider: Реальная логика проверки. Он идет в базу данных и сверяет данные.
4. UserDetailsService: Сервис, который умеет загружать данные пользователя из базы по его имени (username).
5. SecurityContextHolder: «Сейф», куда Spring кладет данные об успешном входе. Пока пользователь в этом сейфе — он считается аутентифицированным.

### 2. Настройка 
В современных версиях (Spring Boot 3+) настраиваем безопасность через создание бина SecurityFilterChain.
```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.disable()) // Отключаем защиту от CSRF для тестов
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/api/public/**").permitAll() // Сюда можно всем
                .anyRequest().authenticated() // Всё остальное — только по логину
            )
            .formLogin(Customizer.withDefaults()) // Включаем стандартную форму логина
            .httpBasic(Customizer.withDefaults()); // Включаем Basic Auth (для Postman)

        return http.build();
    }

    // Хранилище пользователей в памяти (для начала)
    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails user = User.builder()
                .username("admin")
                .password(passwordEncoder().encode("password"))
                .roles("ADMIN")
                .build();
        return new InMemoryUserDetailsManager(user);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(); // Обязательно шифруем пароли!
    }
}
```
### 3. Ключевые понятия
* Principal: Это «текущий пользователь». Обычно это объект UserDetails.
* Granted Authority: Права доступа (роли). Обычно начинаются с префикса ROLE_ (например, ROLE_ADMIN).
* BCryptPasswordEncoder: Стандарт де-факто для шифрования паролей. Spring Security запрещает хранить пароли в открытом виде — приложение просто не запустится или выдаст ошибку.
### 4. Как хранится в БД

Нужно создать свой сервис, который имплементирует интерфейс UserDetailsService.

```java
@Service
public class MyUserDetailsService implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // Ищем пользователя в нашей БД
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        // Превращаем нашего User (Entity) в UserDetails (который понятен Spring Security)
        return new org.springframework.security.core.userdetails.User(
                user.getUsername(),
                user.getPassword(),
                Collections.emptyList() // Список ролей
        );
    }
}
```
## 2.Авторизация
Авторизация отвечает на вопрос "что разрешено делать?". Для этого в Spring security используются аннотации прямо над методами и называется это Method Security.

Чтобы Spring начал видеть аннотации нужно добавить одну аннотацию к твоему классу конфигурации (SecurityConfig): `@EnableMethodSecurity`
### 1.Главные аннотации
* @PreAuthorize: Проверяет права ДО выполнения метода. Самая популярная.
* @PostAuthorize: Проверяет права ПОСЛЕ выполнения (редко, но полезно, если нужно проверить результат метода).
* @Secured: Старый вариант (менее гибкий, чем SpEL-выражения).

Пример использования SpEL (Spring Expression Language):
В @PreAuthorize можно писать целые логические условия.
```java
@Service
public class ProductService {

    // Только пользователи с ролью ADMIN могут удалять
    @PreAuthorize("hasRole('ADMIN')")
    public void deleteProduct(Long id) {
        // логика удаления
    }

    // Либо ADMIN, либо MANAGER
    @PreAuthorize("hasAnyRole('ADMIN', 'MANAGER')")
    public void updateProduct(Long id) {
        // логика обновления
    }
    
    // Можно даже проверить, совпадает ли имя текущего юзера с аргументом метода!
    @PreAuthorize("#username == authentication.name")
    public void updateProfile(String username) {
        // логика
    }
}
```
### 3. Разница между Role и Authority
* Authority (Право): Точечное разрешение. Например: READ_PRIVILEGE, DELETE_PRIVILEGE.
* Role (Роль): Группа прав. В Spring роли всегда должны начинаться с префикса ROLE_.
Если написать hasRole('ADMIN'), Spring внутри ищет authority с именем ROLE_ADMIN.
### 4. Как это работает в цепочке фильтров (Filter Chain)
Когда запрос проходит аутентификацию, объект пользователя (Principal) попадает в SecurityContextHolder. Когда вызывается метод с @PreAuthorize, специальный перехватчик (Interceptor) заглядывает в этот "контейнер", достает список ролей пользователя и сравнивает их с тем, что ты написал в аннотации.

## 3.OAuth2
OAuth 2.0 — это протокол авторизации, который позволяет одному приложению получить ограниченный доступ к ресурсам пользователя на другом сервисе (например, войти в приложение через Google или GitHub) без передачи пароля.

### 1. Основные понятия 
* Владелец ресурса: пользователь который разрешает приложению доступ к своим данным
* Клиент: приложение, которое хочет получить доступ
* Сервер авторизации: сервер, который подтверждает личность пользователя и выдает разрешение
* Сервер ресурсов: сервер, где хранятся данные

### 2. Как это работает
Самый популярный сценарий
1. Запрос: пользователь нажимает "войти через Google" и перенаправляется на сервер Google
2. Получение разрешения: Google спрашивает "разрешить приложение видеть ваш email?" и пользователь соглашается
3. Получение кода: Google отправляет в приложение временный Authorization code
4. Обмен: приложение отправляет этот код обратно на Google, чтобы получить Access token
5. Доступ: с этим токеном идем на сервер ресурсов где получаем нужную информацию(email) 

### 3. Настройка Spring boot
1. Необходимо добавить зависимость(в pom.xml)
```XML
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-oauth2-client</artifactId>
</dependency>
```

2. Нужно зарегистрироваться на сервере авторизации например Google Cloud Console, получить `client-id` и `client-secret` и настроить `application.yml`
```YAML
spring:
  security:
    oauth2:
      client:
        registration:
          google:
            client-id: ВАШ_ID
            client-secret: ВАШ_СЕКРЕТ
            scope: profile, email
```

3. Настроить Spring Security чтобы можно было использовать OAuth2 

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .anyRequest().authenticated() // Все запросы защищены
            )
            .oauth2Login(Customizer.withDefaults()); // Включаем вход через OAuth2

        return http.build();
    }
}
```
## 4.JWT аутентификация
JWT (JSON Web Token) аутентификация — это современный стандарт для создания безопасных и масштабируемых систем. В отличие от сессионной аутентификации, где сервер хранит данные о юзере в памяти, JWT делает твое приложение Stateless (без сохранения состояния).

### 1. Как работает
Сервер один раз проверяет данные пользователя, выдает ему токен и по нему в дальнейшем его проверяет
1. Логин: клиент отправляет логин и пароль 
2. Верификация: сверяем данные в бд 
3. Генерация токена: если все хорошо генерируем токен и отдает клиенту
4. Сохранение токена: клиент сохраняет токен (LocalStorage, Cookies)
5. Запросы: при каждом запросе клиент прикрепляет токен в заголовок запроса `Authorization: Bearer <token>`
6. Валидация: если подпись токена правильная и он валидный(время действия не вышло), запрос выполняется
### 2. Структура JWT
Токен состоит из 3 частей разделенных точками `xxxxx.yyyyy.zzzzz`
* Header(заголовок): тип токена и алгоритм шифрования
* Payload(полезная нагрузка): данные пользователя, они не зашифрованы, поэтому пароль туда класть не надо
* Signature(Подпись): это хеш заголовка, нагрузки и секрета(ключ, фраза, строка, которая лежит на сервере). Это гарантирует, что никто не изменил данные в Payload.

### 3. Реализация в Spring boot
Необходим сервис для генерации JWT токена 
```java
public String generateToken(UserDetails userDetails) {
    Map<String, Object> claims = new HashMap<>(); // Сюда можно добавить роли
    return Jwts.builder()
            .setClaims(claims)
            .setSubject(userDetails.getUsername())
            .setIssuedAt(new Date(System.currentTimeMillis()))
            .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60)) //  час
            .signWith(SignatureAlgorithm.HS256, "SECRET_KEY")
            .compact();
}
```
Также нужен фильтр который будет проверять токен в каждом запросе
```java
@Component
public class JwtRequestFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException, AuthenticationException {

        try {
            String jwt = getJWTFromRequest(request);//достаем чистый токен
            if (StringUtils.hasText(jwt) && tokenProvider.validateToken(jwt, false, SecurityConstants.ACCESS_SECRET)) {//валидация токена: не пустой ли он, не истекло ли время его жизни, верна ли цифровая подпись
                if (!"access".equals(tokenProvider.getTokenType(jwt, false, SecurityConstants.ACCESS_SECRET))) {//проверка типа токена(refresh/access)
                    filterChain.doFilter(request, response);
                    return;
                }
                Long userId = tokenProvider.getUserIdFromToken(jwt, false, SecurityConstants.ACCESS_SECRET);//берем данные из токена для поиска нашего пользователя 
                UserDetails userDetails = customUserDetailsService.loadUserById(userId);
                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                        userDetails, null, userDetails.getAuthorities());//Мы создаем объект Authentication и кладем его в SecurityContextHolder.
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authentication);//пока здесь находится объект, считается что пользователь залогинен

            }
            if (!StringUtils.hasText(jwt)) {
                filterChain.doFilter(request, response);//передаем обработку дальше
                return;
            }

        } catch (AuthenticationException ex) {//если произошла ошибка (токен недействительный) мы очищаем контекст и пользователь получит ошибку 401
            SecurityContextHolder.clearContext();
            throw ex;
        }

        filterChain.doFilter(request, response);
    }
}
```

Также с такой системой входа лучше использовать refresh токен, чтобы пользователю не нужно было логиниться каждые 15 минут, когда клиент получает ошибку авторизации, он отправляет refresh токен и сервер его валидирует и если все хорошо, отдает новый access токен.
Refresh token это такой же jwt token, но его время жизни намного больше и он не оправляется при каждом запросе.
# **Стартеры spring boot**

# **Автоконфигурация**

# **Актуаторы**

# **Встроенный сервер**

# **Hibernate**

## 1. Жизненный цикл сущности

## 2.Отношения

## 3.Транзакции

# **Spring Data**

## 1.Spring Data JPA

## 2.Spring Data Mongodb

## 3.Spring Data JDBC