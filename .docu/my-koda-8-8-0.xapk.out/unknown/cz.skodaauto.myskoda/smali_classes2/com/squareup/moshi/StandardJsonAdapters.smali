.class final Lcom/squareup/moshi/StandardJsonAdapters;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/squareup/moshi/StandardJsonAdapters$ObjectJsonAdapter;,
        Lcom/squareup/moshi/StandardJsonAdapters$EnumJsonAdapter;
    }
.end annotation


# static fields
.field public static final a:Lcom/squareup/moshi/JsonAdapter$Factory;

.field public static final b:Lcom/squareup/moshi/JsonAdapter;

.field public static final c:Lcom/squareup/moshi/JsonAdapter;

.field public static final d:Lcom/squareup/moshi/JsonAdapter;

.field public static final e:Lcom/squareup/moshi/JsonAdapter;

.field public static final f:Lcom/squareup/moshi/JsonAdapter;

.field public static final g:Lcom/squareup/moshi/JsonAdapter;

.field public static final h:Lcom/squareup/moshi/JsonAdapter;

.field public static final i:Lcom/squareup/moshi/JsonAdapter;

.field public static final j:Lcom/squareup/moshi/JsonAdapter;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lcom/squareup/moshi/StandardJsonAdapters$1;

    .line 2
    .line 3
    invoke-direct {v0}, Lcom/squareup/moshi/StandardJsonAdapters$1;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lcom/squareup/moshi/StandardJsonAdapters;->a:Lcom/squareup/moshi/JsonAdapter$Factory;

    .line 7
    .line 8
    new-instance v0, Lcom/squareup/moshi/StandardJsonAdapters$2;

    .line 9
    .line 10
    invoke-direct {v0}, Lcom/squareup/moshi/StandardJsonAdapters$2;-><init>()V

    .line 11
    .line 12
    .line 13
    sput-object v0, Lcom/squareup/moshi/StandardJsonAdapters;->b:Lcom/squareup/moshi/JsonAdapter;

    .line 14
    .line 15
    new-instance v0, Lcom/squareup/moshi/StandardJsonAdapters$3;

    .line 16
    .line 17
    invoke-direct {v0}, Lcom/squareup/moshi/StandardJsonAdapters$3;-><init>()V

    .line 18
    .line 19
    .line 20
    sput-object v0, Lcom/squareup/moshi/StandardJsonAdapters;->c:Lcom/squareup/moshi/JsonAdapter;

    .line 21
    .line 22
    new-instance v0, Lcom/squareup/moshi/StandardJsonAdapters$4;

    .line 23
    .line 24
    invoke-direct {v0}, Lcom/squareup/moshi/StandardJsonAdapters$4;-><init>()V

    .line 25
    .line 26
    .line 27
    sput-object v0, Lcom/squareup/moshi/StandardJsonAdapters;->d:Lcom/squareup/moshi/JsonAdapter;

    .line 28
    .line 29
    new-instance v0, Lcom/squareup/moshi/StandardJsonAdapters$5;

    .line 30
    .line 31
    invoke-direct {v0}, Lcom/squareup/moshi/StandardJsonAdapters$5;-><init>()V

    .line 32
    .line 33
    .line 34
    sput-object v0, Lcom/squareup/moshi/StandardJsonAdapters;->e:Lcom/squareup/moshi/JsonAdapter;

    .line 35
    .line 36
    new-instance v0, Lcom/squareup/moshi/StandardJsonAdapters$6;

    .line 37
    .line 38
    invoke-direct {v0}, Lcom/squareup/moshi/StandardJsonAdapters$6;-><init>()V

    .line 39
    .line 40
    .line 41
    sput-object v0, Lcom/squareup/moshi/StandardJsonAdapters;->f:Lcom/squareup/moshi/JsonAdapter;

    .line 42
    .line 43
    new-instance v0, Lcom/squareup/moshi/StandardJsonAdapters$7;

    .line 44
    .line 45
    invoke-direct {v0}, Lcom/squareup/moshi/StandardJsonAdapters$7;-><init>()V

    .line 46
    .line 47
    .line 48
    sput-object v0, Lcom/squareup/moshi/StandardJsonAdapters;->g:Lcom/squareup/moshi/JsonAdapter;

    .line 49
    .line 50
    new-instance v0, Lcom/squareup/moshi/StandardJsonAdapters$8;

    .line 51
    .line 52
    invoke-direct {v0}, Lcom/squareup/moshi/StandardJsonAdapters$8;-><init>()V

    .line 53
    .line 54
    .line 55
    sput-object v0, Lcom/squareup/moshi/StandardJsonAdapters;->h:Lcom/squareup/moshi/JsonAdapter;

    .line 56
    .line 57
    new-instance v0, Lcom/squareup/moshi/StandardJsonAdapters$9;

    .line 58
    .line 59
    invoke-direct {v0}, Lcom/squareup/moshi/StandardJsonAdapters$9;-><init>()V

    .line 60
    .line 61
    .line 62
    sput-object v0, Lcom/squareup/moshi/StandardJsonAdapters;->i:Lcom/squareup/moshi/JsonAdapter;

    .line 63
    .line 64
    new-instance v0, Lcom/squareup/moshi/StandardJsonAdapters$10;

    .line 65
    .line 66
    invoke-direct {v0}, Lcom/squareup/moshi/StandardJsonAdapters$10;-><init>()V

    .line 67
    .line 68
    .line 69
    sput-object v0, Lcom/squareup/moshi/StandardJsonAdapters;->j:Lcom/squareup/moshi/JsonAdapter;

    .line 70
    .line 71
    return-void
.end method

.method private constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static a(Lcom/squareup/moshi/JsonReader;Ljava/lang/String;II)I
    .locals 3

    .line 1
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonReader;->l()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-lt v0, p2, :cond_0

    .line 6
    .line 7
    if-gt v0, p3, :cond_0

    .line 8
    .line 9
    return v0

    .line 10
    :cond_0
    new-instance p2, Lcom/squareup/moshi/JsonDataException;

    .line 11
    .line 12
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonReader;->g()Ljava/lang/String;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    const-string p3, " but was "

    .line 17
    .line 18
    const-string v1, " at path "

    .line 19
    .line 20
    const-string v2, "Expected "

    .line 21
    .line 22
    invoke-static {v2, v0, p1, p3, v1}, La7/g0;->m(Ljava/lang/String;ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 23
    .line 24
    .line 25
    move-result-object p1

    .line 26
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 27
    .line 28
    .line 29
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    invoke-direct {p2, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 34
    .line 35
    .line 36
    throw p2
.end method
