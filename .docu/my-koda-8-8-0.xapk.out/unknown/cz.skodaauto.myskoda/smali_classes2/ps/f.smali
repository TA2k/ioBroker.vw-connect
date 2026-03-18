.class public final Lps/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lzs/d;


# static fields
.field public static final a:Lps/f;

.field public static final b:Lzs/c;

.field public static final c:Lzs/c;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lps/f;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lps/f;->a:Lps/f;

    .line 7
    .line 8
    const-string v0, "filename"

    .line 9
    .line 10
    invoke-static {v0}, Lzs/c;->b(Ljava/lang/String;)Lzs/c;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    sput-object v0, Lps/f;->b:Lzs/c;

    .line 15
    .line 16
    const-string v0, "contents"

    .line 17
    .line 18
    invoke-static {v0}, Lzs/c;->b(Ljava/lang/String;)Lzs/c;

    .line 19
    .line 20
    .line 21
    move-result-object v0

    .line 22
    sput-object v0, Lps/f;->c:Lzs/c;

    .line 23
    .line 24
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/Object;Ljava/lang/Object;)V
    .locals 1

    .line 1
    check-cast p1, Lps/r1;

    .line 2
    .line 3
    check-cast p2, Lzs/e;

    .line 4
    .line 5
    check-cast p1, Lps/h0;

    .line 6
    .line 7
    iget-object p0, p1, Lps/h0;->a:Ljava/lang/String;

    .line 8
    .line 9
    sget-object v0, Lps/f;->b:Lzs/c;

    .line 10
    .line 11
    invoke-interface {p2, v0, p0}, Lzs/e;->a(Lzs/c;Ljava/lang/Object;)Lzs/e;

    .line 12
    .line 13
    .line 14
    sget-object p0, Lps/f;->c:Lzs/c;

    .line 15
    .line 16
    iget-object p1, p1, Lps/h0;->b:[B

    .line 17
    .line 18
    invoke-interface {p2, p0, p1}, Lzs/e;->a(Lzs/c;Ljava/lang/Object;)Lzs/e;

    .line 19
    .line 20
    .line 21
    return-void
.end method
