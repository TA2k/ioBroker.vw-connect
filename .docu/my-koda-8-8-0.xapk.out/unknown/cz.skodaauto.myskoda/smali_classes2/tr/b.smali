.class public final Ltr/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final g:[Ljava/lang/String;

.field public static final h:Ljava/text/SimpleDateFormat;


# instance fields
.field public final a:Ljava/lang/String;

.field public final b:Ljava/lang/String;

.field public final c:Ljava/lang/String;

.field public final d:Ljava/util/Date;

.field public final e:J

.field public final f:J


# direct methods
.method static constructor <clinit>()V
    .locals 5

    .line 1
    const-string v0, "triggerTimeoutMillis"

    .line 2
    .line 3
    const-string v1, "variantId"

    .line 4
    .line 5
    const-string v2, "experimentId"

    .line 6
    .line 7
    const-string v3, "experimentStartTime"

    .line 8
    .line 9
    const-string v4, "timeToLiveMillis"

    .line 10
    .line 11
    filled-new-array {v2, v3, v4, v0, v1}, [Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    sput-object v0, Ltr/b;->g:[Ljava/lang/String;

    .line 16
    .line 17
    new-instance v0, Ljava/text/SimpleDateFormat;

    .line 18
    .line 19
    const-string v1, "yyyy-MM-dd\'T\'HH:mm:ss"

    .line 20
    .line 21
    sget-object v2, Ljava/util/Locale;->US:Ljava/util/Locale;

    .line 22
    .line 23
    invoke-direct {v0, v1, v2}, Ljava/text/SimpleDateFormat;-><init>(Ljava/lang/String;Ljava/util/Locale;)V

    .line 24
    .line 25
    .line 26
    sput-object v0, Ltr/b;->h:Ljava/text/SimpleDateFormat;

    .line 27
    .line 28
    return-void
.end method

.method public constructor <init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/util/Date;JJ)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ltr/b;->a:Ljava/lang/String;

    .line 5
    .line 6
    iput-object p2, p0, Ltr/b;->b:Ljava/lang/String;

    .line 7
    .line 8
    iput-object p3, p0, Ltr/b;->c:Ljava/lang/String;

    .line 9
    .line 10
    iput-object p4, p0, Ltr/b;->d:Ljava/util/Date;

    .line 11
    .line 12
    iput-wide p5, p0, Ltr/b;->e:J

    .line 13
    .line 14
    iput-wide p7, p0, Ltr/b;->f:J

    .line 15
    .line 16
    return-void
.end method


# virtual methods
.method public final a()Lwr/a;
    .locals 3

    .line 1
    new-instance v0, Lwr/a;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    const-string v1, "frc"

    .line 7
    .line 8
    iput-object v1, v0, Lwr/a;->a:Ljava/lang/String;

    .line 9
    .line 10
    iget-object v1, p0, Ltr/b;->d:Ljava/util/Date;

    .line 11
    .line 12
    invoke-virtual {v1}, Ljava/util/Date;->getTime()J

    .line 13
    .line 14
    .line 15
    move-result-wide v1

    .line 16
    iput-wide v1, v0, Lwr/a;->m:J

    .line 17
    .line 18
    iget-object v1, p0, Ltr/b;->a:Ljava/lang/String;

    .line 19
    .line 20
    iput-object v1, v0, Lwr/a;->b:Ljava/lang/String;

    .line 21
    .line 22
    iget-object v1, p0, Ltr/b;->b:Ljava/lang/String;

    .line 23
    .line 24
    iput-object v1, v0, Lwr/a;->c:Ljava/lang/Object;

    .line 25
    .line 26
    iget-object v1, p0, Ltr/b;->c:Ljava/lang/String;

    .line 27
    .line 28
    invoke-static {v1}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 29
    .line 30
    .line 31
    move-result v2

    .line 32
    if-eqz v2, :cond_0

    .line 33
    .line 34
    const/4 v1, 0x0

    .line 35
    :cond_0
    iput-object v1, v0, Lwr/a;->d:Ljava/lang/String;

    .line 36
    .line 37
    iget-wide v1, p0, Ltr/b;->e:J

    .line 38
    .line 39
    iput-wide v1, v0, Lwr/a;->e:J

    .line 40
    .line 41
    iget-wide v1, p0, Ltr/b;->f:J

    .line 42
    .line 43
    iput-wide v1, v0, Lwr/a;->j:J

    .line 44
    .line 45
    return-object v0
.end method
