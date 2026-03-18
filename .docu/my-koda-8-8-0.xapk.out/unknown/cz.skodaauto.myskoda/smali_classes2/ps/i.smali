.class public final Lps/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lzs/d;


# static fields
.field public static final a:Lps/i;

.field public static final b:Lzs/c;

.field public static final c:Lzs/c;

.field public static final d:Lzs/c;

.field public static final e:Lzs/c;

.field public static final f:Lzs/c;

.field public static final g:Lzs/c;

.field public static final h:Lzs/c;

.field public static final i:Lzs/c;

.field public static final j:Lzs/c;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lps/i;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lps/i;->a:Lps/i;

    .line 7
    .line 8
    const-string v0, "arch"

    .line 9
    .line 10
    invoke-static {v0}, Lzs/c;->b(Ljava/lang/String;)Lzs/c;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    sput-object v0, Lps/i;->b:Lzs/c;

    .line 15
    .line 16
    const-string v0, "model"

    .line 17
    .line 18
    invoke-static {v0}, Lzs/c;->b(Ljava/lang/String;)Lzs/c;

    .line 19
    .line 20
    .line 21
    move-result-object v0

    .line 22
    sput-object v0, Lps/i;->c:Lzs/c;

    .line 23
    .line 24
    const-string v0, "cores"

    .line 25
    .line 26
    invoke-static {v0}, Lzs/c;->b(Ljava/lang/String;)Lzs/c;

    .line 27
    .line 28
    .line 29
    move-result-object v0

    .line 30
    sput-object v0, Lps/i;->d:Lzs/c;

    .line 31
    .line 32
    const-string v0, "ram"

    .line 33
    .line 34
    invoke-static {v0}, Lzs/c;->b(Ljava/lang/String;)Lzs/c;

    .line 35
    .line 36
    .line 37
    move-result-object v0

    .line 38
    sput-object v0, Lps/i;->e:Lzs/c;

    .line 39
    .line 40
    const-string v0, "diskSpace"

    .line 41
    .line 42
    invoke-static {v0}, Lzs/c;->b(Ljava/lang/String;)Lzs/c;

    .line 43
    .line 44
    .line 45
    move-result-object v0

    .line 46
    sput-object v0, Lps/i;->f:Lzs/c;

    .line 47
    .line 48
    const-string v0, "simulator"

    .line 49
    .line 50
    invoke-static {v0}, Lzs/c;->b(Ljava/lang/String;)Lzs/c;

    .line 51
    .line 52
    .line 53
    move-result-object v0

    .line 54
    sput-object v0, Lps/i;->g:Lzs/c;

    .line 55
    .line 56
    const-string v0, "state"

    .line 57
    .line 58
    invoke-static {v0}, Lzs/c;->b(Ljava/lang/String;)Lzs/c;

    .line 59
    .line 60
    .line 61
    move-result-object v0

    .line 62
    sput-object v0, Lps/i;->h:Lzs/c;

    .line 63
    .line 64
    const-string v0, "manufacturer"

    .line 65
    .line 66
    invoke-static {v0}, Lzs/c;->b(Ljava/lang/String;)Lzs/c;

    .line 67
    .line 68
    .line 69
    move-result-object v0

    .line 70
    sput-object v0, Lps/i;->i:Lzs/c;

    .line 71
    .line 72
    const-string v0, "modelClass"

    .line 73
    .line 74
    invoke-static {v0}, Lzs/c;->b(Ljava/lang/String;)Lzs/c;

    .line 75
    .line 76
    .line 77
    move-result-object v0

    .line 78
    sput-object v0, Lps/i;->j:Lzs/c;

    .line 79
    .line 80
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/Object;Ljava/lang/Object;)V
    .locals 2

    .line 1
    check-cast p1, Lps/v1;

    .line 2
    .line 3
    check-cast p2, Lzs/e;

    .line 4
    .line 5
    check-cast p1, Lps/n0;

    .line 6
    .line 7
    iget p0, p1, Lps/n0;->a:I

    .line 8
    .line 9
    sget-object v0, Lps/i;->b:Lzs/c;

    .line 10
    .line 11
    invoke-interface {p2, v0, p0}, Lzs/e;->g(Lzs/c;I)Lzs/e;

    .line 12
    .line 13
    .line 14
    sget-object p0, Lps/i;->c:Lzs/c;

    .line 15
    .line 16
    iget-object v0, p1, Lps/n0;->b:Ljava/lang/String;

    .line 17
    .line 18
    invoke-interface {p2, p0, v0}, Lzs/e;->a(Lzs/c;Ljava/lang/Object;)Lzs/e;

    .line 19
    .line 20
    .line 21
    sget-object p0, Lps/i;->d:Lzs/c;

    .line 22
    .line 23
    iget v0, p1, Lps/n0;->c:I

    .line 24
    .line 25
    invoke-interface {p2, p0, v0}, Lzs/e;->g(Lzs/c;I)Lzs/e;

    .line 26
    .line 27
    .line 28
    sget-object p0, Lps/i;->e:Lzs/c;

    .line 29
    .line 30
    iget-wide v0, p1, Lps/n0;->d:J

    .line 31
    .line 32
    invoke-interface {p2, p0, v0, v1}, Lzs/e;->f(Lzs/c;J)Lzs/e;

    .line 33
    .line 34
    .line 35
    sget-object p0, Lps/i;->f:Lzs/c;

    .line 36
    .line 37
    iget-wide v0, p1, Lps/n0;->e:J

    .line 38
    .line 39
    invoke-interface {p2, p0, v0, v1}, Lzs/e;->f(Lzs/c;J)Lzs/e;

    .line 40
    .line 41
    .line 42
    sget-object p0, Lps/i;->g:Lzs/c;

    .line 43
    .line 44
    iget-boolean v0, p1, Lps/n0;->f:Z

    .line 45
    .line 46
    invoke-interface {p2, p0, v0}, Lzs/e;->d(Lzs/c;Z)Lzs/e;

    .line 47
    .line 48
    .line 49
    sget-object p0, Lps/i;->h:Lzs/c;

    .line 50
    .line 51
    iget v0, p1, Lps/n0;->g:I

    .line 52
    .line 53
    invoke-interface {p2, p0, v0}, Lzs/e;->g(Lzs/c;I)Lzs/e;

    .line 54
    .line 55
    .line 56
    sget-object p0, Lps/i;->i:Lzs/c;

    .line 57
    .line 58
    iget-object v0, p1, Lps/n0;->h:Ljava/lang/String;

    .line 59
    .line 60
    invoke-interface {p2, p0, v0}, Lzs/e;->a(Lzs/c;Ljava/lang/Object;)Lzs/e;

    .line 61
    .line 62
    .line 63
    sget-object p0, Lps/i;->j:Lzs/c;

    .line 64
    .line 65
    iget-object p1, p1, Lps/n0;->i:Ljava/lang/String;

    .line 66
    .line 67
    invoke-interface {p2, p0, p1}, Lzs/e;->a(Lzs/c;Ljava/lang/Object;)Lzs/e;

    .line 68
    .line 69
    .line 70
    return-void
.end method
