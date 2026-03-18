.class public final Lhu/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lzs/d;


# static fields
.field public static final a:Lhu/h;

.field public static final b:Lzs/c;

.field public static final c:Lzs/c;

.field public static final d:Lzs/c;

.field public static final e:Lzs/c;

.field public static final f:Lzs/c;

.field public static final g:Lzs/c;

.field public static final h:Lzs/c;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lhu/h;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lhu/h;->a:Lhu/h;

    .line 7
    .line 8
    const-string v0, "sessionId"

    .line 9
    .line 10
    invoke-static {v0}, Lzs/c;->b(Ljava/lang/String;)Lzs/c;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    sput-object v0, Lhu/h;->b:Lzs/c;

    .line 15
    .line 16
    const-string v0, "firstSessionId"

    .line 17
    .line 18
    invoke-static {v0}, Lzs/c;->b(Ljava/lang/String;)Lzs/c;

    .line 19
    .line 20
    .line 21
    move-result-object v0

    .line 22
    sput-object v0, Lhu/h;->c:Lzs/c;

    .line 23
    .line 24
    const-string v0, "sessionIndex"

    .line 25
    .line 26
    invoke-static {v0}, Lzs/c;->b(Ljava/lang/String;)Lzs/c;

    .line 27
    .line 28
    .line 29
    move-result-object v0

    .line 30
    sput-object v0, Lhu/h;->d:Lzs/c;

    .line 31
    .line 32
    const-string v0, "eventTimestampUs"

    .line 33
    .line 34
    invoke-static {v0}, Lzs/c;->b(Ljava/lang/String;)Lzs/c;

    .line 35
    .line 36
    .line 37
    move-result-object v0

    .line 38
    sput-object v0, Lhu/h;->e:Lzs/c;

    .line 39
    .line 40
    const-string v0, "dataCollectionStatus"

    .line 41
    .line 42
    invoke-static {v0}, Lzs/c;->b(Ljava/lang/String;)Lzs/c;

    .line 43
    .line 44
    .line 45
    move-result-object v0

    .line 46
    sput-object v0, Lhu/h;->f:Lzs/c;

    .line 47
    .line 48
    const-string v0, "firebaseInstallationId"

    .line 49
    .line 50
    invoke-static {v0}, Lzs/c;->b(Ljava/lang/String;)Lzs/c;

    .line 51
    .line 52
    .line 53
    move-result-object v0

    .line 54
    sput-object v0, Lhu/h;->g:Lzs/c;

    .line 55
    .line 56
    const-string v0, "firebaseAuthenticationToken"

    .line 57
    .line 58
    invoke-static {v0}, Lzs/c;->b(Ljava/lang/String;)Lzs/c;

    .line 59
    .line 60
    .line 61
    move-result-object v0

    .line 62
    sput-object v0, Lhu/h;->h:Lzs/c;

    .line 63
    .line 64
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/Object;Ljava/lang/Object;)V
    .locals 2

    .line 1
    check-cast p1, Lhu/q0;

    .line 2
    .line 3
    check-cast p2, Lzs/e;

    .line 4
    .line 5
    sget-object p0, Lhu/h;->b:Lzs/c;

    .line 6
    .line 7
    iget-object v0, p1, Lhu/q0;->a:Ljava/lang/String;

    .line 8
    .line 9
    invoke-interface {p2, p0, v0}, Lzs/e;->a(Lzs/c;Ljava/lang/Object;)Lzs/e;

    .line 10
    .line 11
    .line 12
    sget-object p0, Lhu/h;->c:Lzs/c;

    .line 13
    .line 14
    iget-object v0, p1, Lhu/q0;->b:Ljava/lang/String;

    .line 15
    .line 16
    invoke-interface {p2, p0, v0}, Lzs/e;->a(Lzs/c;Ljava/lang/Object;)Lzs/e;

    .line 17
    .line 18
    .line 19
    sget-object p0, Lhu/h;->d:Lzs/c;

    .line 20
    .line 21
    iget v0, p1, Lhu/q0;->c:I

    .line 22
    .line 23
    invoke-interface {p2, p0, v0}, Lzs/e;->g(Lzs/c;I)Lzs/e;

    .line 24
    .line 25
    .line 26
    sget-object p0, Lhu/h;->e:Lzs/c;

    .line 27
    .line 28
    iget-wide v0, p1, Lhu/q0;->d:J

    .line 29
    .line 30
    invoke-interface {p2, p0, v0, v1}, Lzs/e;->f(Lzs/c;J)Lzs/e;

    .line 31
    .line 32
    .line 33
    sget-object p0, Lhu/h;->f:Lzs/c;

    .line 34
    .line 35
    iget-object v0, p1, Lhu/q0;->e:Lhu/k;

    .line 36
    .line 37
    invoke-interface {p2, p0, v0}, Lzs/e;->a(Lzs/c;Ljava/lang/Object;)Lzs/e;

    .line 38
    .line 39
    .line 40
    sget-object p0, Lhu/h;->g:Lzs/c;

    .line 41
    .line 42
    iget-object v0, p1, Lhu/q0;->f:Ljava/lang/String;

    .line 43
    .line 44
    invoke-interface {p2, p0, v0}, Lzs/e;->a(Lzs/c;Ljava/lang/Object;)Lzs/e;

    .line 45
    .line 46
    .line 47
    sget-object p0, Lhu/h;->h:Lzs/c;

    .line 48
    .line 49
    iget-object p1, p1, Lhu/q0;->g:Ljava/lang/String;

    .line 50
    .line 51
    invoke-interface {p2, p0, p1}, Lzs/e;->a(Lzs/c;Ljava/lang/Object;)Lzs/e;

    .line 52
    .line 53
    .line 54
    return-void
.end method
