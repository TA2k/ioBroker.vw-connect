.class public final Lps/l;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lzs/d;


# static fields
.field public static final a:Lps/l;

.field public static final b:Lzs/c;

.field public static final c:Lzs/c;

.field public static final d:Lzs/c;

.field public static final e:Lzs/c;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lps/l;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lps/l;->a:Lps/l;

    .line 7
    .line 8
    const-string v0, "baseAddress"

    .line 9
    .line 10
    invoke-static {v0}, Lzs/c;->b(Ljava/lang/String;)Lzs/c;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    sput-object v0, Lps/l;->b:Lzs/c;

    .line 15
    .line 16
    const-string v0, "size"

    .line 17
    .line 18
    invoke-static {v0}, Lzs/c;->b(Ljava/lang/String;)Lzs/c;

    .line 19
    .line 20
    .line 21
    move-result-object v0

    .line 22
    sput-object v0, Lps/l;->c:Lzs/c;

    .line 23
    .line 24
    const-string v0, "name"

    .line 25
    .line 26
    invoke-static {v0}, Lzs/c;->b(Ljava/lang/String;)Lzs/c;

    .line 27
    .line 28
    .line 29
    move-result-object v0

    .line 30
    sput-object v0, Lps/l;->d:Lzs/c;

    .line 31
    .line 32
    const-string v0, "uuid"

    .line 33
    .line 34
    invoke-static {v0}, Lzs/c;->b(Ljava/lang/String;)Lzs/c;

    .line 35
    .line 36
    .line 37
    move-result-object v0

    .line 38
    sput-object v0, Lps/l;->e:Lzs/c;

    .line 39
    .line 40
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/Object;Ljava/lang/Object;)V
    .locals 2

    .line 1
    check-cast p1, Lps/w1;

    .line 2
    .line 3
    check-cast p2, Lzs/e;

    .line 4
    .line 5
    check-cast p1, Lps/s0;

    .line 6
    .line 7
    iget-wide v0, p1, Lps/s0;->a:J

    .line 8
    .line 9
    sget-object p0, Lps/l;->b:Lzs/c;

    .line 10
    .line 11
    invoke-interface {p2, p0, v0, v1}, Lzs/e;->f(Lzs/c;J)Lzs/e;

    .line 12
    .line 13
    .line 14
    sget-object p0, Lps/l;->c:Lzs/c;

    .line 15
    .line 16
    iget-wide v0, p1, Lps/s0;->b:J

    .line 17
    .line 18
    invoke-interface {p2, p0, v0, v1}, Lzs/e;->f(Lzs/c;J)Lzs/e;

    .line 19
    .line 20
    .line 21
    sget-object p0, Lps/l;->d:Lzs/c;

    .line 22
    .line 23
    iget-object v0, p1, Lps/s0;->c:Ljava/lang/String;

    .line 24
    .line 25
    invoke-interface {p2, p0, v0}, Lzs/e;->a(Lzs/c;Ljava/lang/Object;)Lzs/e;

    .line 26
    .line 27
    .line 28
    iget-object p0, p1, Lps/s0;->d:Ljava/lang/String;

    .line 29
    .line 30
    if-eqz p0, :cond_0

    .line 31
    .line 32
    sget-object p1, Lps/n2;->a:Ljava/nio/charset/Charset;

    .line 33
    .line 34
    invoke-virtual {p0, p1}, Ljava/lang/String;->getBytes(Ljava/nio/charset/Charset;)[B

    .line 35
    .line 36
    .line 37
    move-result-object p0

    .line 38
    goto :goto_0

    .line 39
    :cond_0
    const/4 p0, 0x0

    .line 40
    :goto_0
    sget-object p1, Lps/l;->e:Lzs/c;

    .line 41
    .line 42
    invoke-interface {p2, p1, p0}, Lzs/e;->a(Lzs/c;Ljava/lang/Object;)Lzs/e;

    .line 43
    .line 44
    .line 45
    return-void
.end method
