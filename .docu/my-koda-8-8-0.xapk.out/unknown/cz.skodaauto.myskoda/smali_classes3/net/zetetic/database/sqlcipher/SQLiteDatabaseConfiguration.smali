.class public final Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field private static final EMAIL_IN_DB_PATTERN:Ljava/util/regex/Pattern;

.field public static final MEMORY_DB_PATH:Ljava/lang/String; = ":memory:"


# instance fields
.field public final customFunctions:Ljava/util/ArrayList;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/ArrayList<",
            "Lnet/zetetic/database/sqlcipher/SQLiteCustomFunction;",
            ">;"
        }
    .end annotation
.end field

.field public databaseHook:Lnet/zetetic/database/sqlcipher/SQLiteDatabaseHook;

.field public foreignKeyConstraintsEnabled:Z

.field public final label:Ljava/lang/String;

.field public locale:Ljava/util/Locale;

.field public maxSqlCacheSize:I

.field public openFlags:I

.field public password:[B

.field public final path:Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-string v0, "[\\w\\.\\-]+@[\\w\\.\\-]+"

    .line 2
    .line 3
    invoke-static {v0}, Ljava/util/regex/Pattern;->compile(Ljava/lang/String;)Ljava/util/regex/Pattern;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sput-object v0, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->EMAIL_IN_DB_PATTERN:Ljava/util/regex/Pattern;

    .line 8
    .line 9
    return-void
.end method

.method public constructor <init>(Ljava/lang/String;I)V
    .locals 1

    const/4 v0, 0x0

    .line 1
    invoke-direct {p0, p1, p2, v0, v0}, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;-><init>(Ljava/lang/String;I[BLnet/zetetic/database/sqlcipher/SQLiteDatabaseHook;)V

    return-void
.end method

.method public constructor <init>(Ljava/lang/String;I[BLnet/zetetic/database/sqlcipher/SQLiteDatabaseHook;)V
    .locals 1

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 3
    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    iput-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->customFunctions:Ljava/util/ArrayList;

    if-eqz p1, :cond_0

    .line 4
    iput-object p1, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->path:Ljava/lang/String;

    .line 5
    invoke-static {p1}, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->stripPathForLogs(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p1

    iput-object p1, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->label:Ljava/lang/String;

    .line 6
    iput p2, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->openFlags:I

    .line 7
    iput-object p3, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->password:[B

    .line 8
    iput-object p4, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->databaseHook:Lnet/zetetic/database/sqlcipher/SQLiteDatabaseHook;

    const/16 p1, 0x19

    .line 9
    iput p1, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->maxSqlCacheSize:I

    .line 10
    invoke-static {}, Ljava/util/Locale;->getDefault()Ljava/util/Locale;

    move-result-object p1

    iput-object p1, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->locale:Ljava/util/Locale;

    return-void

    .line 11
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    const-string p1, "path must not be null."

    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p0
.end method

.method public constructor <init>(Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;)V
    .locals 1

    .line 12
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 13
    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    iput-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->customFunctions:Ljava/util/ArrayList;

    if-eqz p1, :cond_0

    .line 14
    iget-object v0, p1, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->path:Ljava/lang/String;

    iput-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->path:Ljava/lang/String;

    .line 15
    iget-object v0, p1, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->label:Ljava/lang/String;

    iput-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->label:Ljava/lang/String;

    .line 16
    invoke-virtual {p0, p1}, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->updateParametersFrom(Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;)V

    return-void

    .line 17
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    const-string p1, "other must not be null."

    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p0
.end method

.method private static stripPathForLogs(Ljava/lang/String;)Ljava/lang/String;
    .locals 2

    .line 1
    const/16 v0, 0x3f

    .line 2
    .line 3
    invoke-virtual {p0, v0}, Ljava/lang/String;->indexOf(I)I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-ltz v0, :cond_0

    .line 8
    .line 9
    const/4 v1, 0x0

    .line 10
    invoke-virtual {p0, v1, v0}, Ljava/lang/String;->subSequence(II)Ljava/lang/CharSequence;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Ljava/lang/String;

    .line 15
    .line 16
    :cond_0
    const/16 v0, 0x40

    .line 17
    .line 18
    invoke-virtual {p0, v0}, Ljava/lang/String;->indexOf(I)I

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    const/4 v1, -0x1

    .line 23
    if-ne v0, v1, :cond_1

    .line 24
    .line 25
    return-object p0

    .line 26
    :cond_1
    sget-object v0, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->EMAIL_IN_DB_PATTERN:Ljava/util/regex/Pattern;

    .line 27
    .line 28
    invoke-virtual {v0, p0}, Ljava/util/regex/Pattern;->matcher(Ljava/lang/CharSequence;)Ljava/util/regex/Matcher;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    const-string v0, "XX@YY"

    .line 33
    .line 34
    invoke-virtual {p0, v0}, Ljava/util/regex/Matcher;->replaceAll(Ljava/lang/String;)Ljava/lang/String;

    .line 35
    .line 36
    .line 37
    move-result-object p0

    .line 38
    return-object p0
.end method


# virtual methods
.method public isInMemoryDb()Z
    .locals 1

    .line 1
    iget-object p0, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->path:Ljava/lang/String;

    .line 2
    .line 3
    const-string v0, ":memory:"

    .line 4
    .line 5
    invoke-virtual {p0, v0}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0
.end method

.method public updateParametersFrom(Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;)V
    .locals 2

    .line 1
    if-eqz p1, :cond_1

    .line 2
    .line 3
    iget-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->path:Ljava/lang/String;

    .line 4
    .line 5
    iget-object v1, p1, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->path:Ljava/lang/String;

    .line 6
    .line 7
    invoke-virtual {v0, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    if-eqz v0, :cond_0

    .line 12
    .line 13
    iget v0, p1, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->openFlags:I

    .line 14
    .line 15
    iput v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->openFlags:I

    .line 16
    .line 17
    iget v0, p1, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->maxSqlCacheSize:I

    .line 18
    .line 19
    iput v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->maxSqlCacheSize:I

    .line 20
    .line 21
    iget-object v0, p1, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->locale:Ljava/util/Locale;

    .line 22
    .line 23
    iput-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->locale:Ljava/util/Locale;

    .line 24
    .line 25
    iget-boolean v0, p1, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->foreignKeyConstraintsEnabled:Z

    .line 26
    .line 27
    iput-boolean v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->foreignKeyConstraintsEnabled:Z

    .line 28
    .line 29
    iget-object v0, p1, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->password:[B

    .line 30
    .line 31
    iput-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->password:[B

    .line 32
    .line 33
    iget-object v0, p1, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->databaseHook:Lnet/zetetic/database/sqlcipher/SQLiteDatabaseHook;

    .line 34
    .line 35
    iput-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->databaseHook:Lnet/zetetic/database/sqlcipher/SQLiteDatabaseHook;

    .line 36
    .line 37
    iget-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->customFunctions:Ljava/util/ArrayList;

    .line 38
    .line 39
    invoke-virtual {v0}, Ljava/util/ArrayList;->clear()V

    .line 40
    .line 41
    .line 42
    iget-object p0, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->customFunctions:Ljava/util/ArrayList;

    .line 43
    .line 44
    iget-object p1, p1, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->customFunctions:Ljava/util/ArrayList;

    .line 45
    .line 46
    invoke-virtual {p0, p1}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 47
    .line 48
    .line 49
    return-void

    .line 50
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 51
    .line 52
    const-string p1, "other configuration must refer to the same database."

    .line 53
    .line 54
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 55
    .line 56
    .line 57
    throw p0

    .line 58
    :cond_1
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 59
    .line 60
    const-string p1, "other must not be null."

    .line 61
    .line 62
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 63
    .line 64
    .line 65
    throw p0
.end method
