.class public final Lps/o;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lzs/d;


# static fields
.field public static final a:Lps/o;

.field public static final b:Lzs/c;

.field public static final c:Lzs/c;

.field public static final d:Lzs/c;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lps/o;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lps/o;->a:Lps/o;

    .line 7
    .line 8
    const-string v0, "name"

    .line 9
    .line 10
    invoke-static {v0}, Lzs/c;->b(Ljava/lang/String;)Lzs/c;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    sput-object v0, Lps/o;->b:Lzs/c;

    .line 15
    .line 16
    const-string v0, "code"

    .line 17
    .line 18
    invoke-static {v0}, Lzs/c;->b(Ljava/lang/String;)Lzs/c;

    .line 19
    .line 20
    .line 21
    move-result-object v0

    .line 22
    sput-object v0, Lps/o;->c:Lzs/c;

    .line 23
    .line 24
    const-string v0, "address"

    .line 25
    .line 26
    invoke-static {v0}, Lzs/c;->b(Ljava/lang/String;)Lzs/c;

    .line 27
    .line 28
    .line 29
    move-result-object v0

    .line 30
    sput-object v0, Lps/o;->d:Lzs/c;

    .line 31
    .line 32
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/Object;Ljava/lang/Object;)V
    .locals 2

    .line 1
    check-cast p1, Lps/y1;

    .line 2
    .line 3
    check-cast p2, Lzs/e;

    .line 4
    .line 5
    check-cast p1, Lps/u0;

    .line 6
    .line 7
    iget-object p0, p1, Lps/u0;->a:Ljava/lang/String;

    .line 8
    .line 9
    sget-object v0, Lps/o;->b:Lzs/c;

    .line 10
    .line 11
    invoke-interface {p2, v0, p0}, Lzs/e;->a(Lzs/c;Ljava/lang/Object;)Lzs/e;

    .line 12
    .line 13
    .line 14
    sget-object p0, Lps/o;->c:Lzs/c;

    .line 15
    .line 16
    iget-object v0, p1, Lps/u0;->b:Ljava/lang/String;

    .line 17
    .line 18
    invoke-interface {p2, p0, v0}, Lzs/e;->a(Lzs/c;Ljava/lang/Object;)Lzs/e;

    .line 19
    .line 20
    .line 21
    sget-object p0, Lps/o;->d:Lzs/c;

    .line 22
    .line 23
    iget-wide v0, p1, Lps/u0;->c:J

    .line 24
    .line 25
    invoke-interface {p2, p0, v0, v1}, Lzs/e;->f(Lzs/c;J)Lzs/e;

    .line 26
    .line 27
    .line 28
    return-void
.end method
