.class public final Lzq0/b;
.super Ljp/he;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic a:Lkotlin/jvm/internal/k;

.field public final synthetic b:Lkotlin/jvm/internal/k;

.field public final synthetic c:Ljava/lang/String;

.field public final synthetic d:Ljavax/crypto/Cipher;


# direct methods
.method public constructor <init>(Lay0/n;Lay0/n;Ljava/lang/String;Ljavax/crypto/Cipher;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    check-cast p1, Lkotlin/jvm/internal/k;

    .line 5
    .line 6
    iput-object p1, p0, Lzq0/b;->a:Lkotlin/jvm/internal/k;

    .line 7
    .line 8
    check-cast p2, Lkotlin/jvm/internal/k;

    .line 9
    .line 10
    iput-object p2, p0, Lzq0/b;->b:Lkotlin/jvm/internal/k;

    .line 11
    .line 12
    iput-object p3, p0, Lzq0/b;->c:Ljava/lang/String;

    .line 13
    .line 14
    iput-object p4, p0, Lzq0/b;->d:Ljavax/crypto/Cipher;

    .line 15
    .line 16
    return-void
.end method


# virtual methods
.method public final e(ILjava/lang/CharSequence;)V
    .locals 1

    .line 1
    const-string v0, "errorString"

    .line 2
    .line 3
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lzq0/b;->a:Lkotlin/jvm/internal/k;

    .line 7
    .line 8
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 9
    .line 10
    .line 11
    move-result-object p1

    .line 12
    invoke-interface {p0, p2, p1}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    return-void
.end method

.method public final f(Lq/n;)V
    .locals 1

    .line 1
    const-string v0, "result"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance p1, Lyq0/k;

    .line 7
    .line 8
    iget-object v0, p0, Lzq0/b;->c:Ljava/lang/String;

    .line 9
    .line 10
    invoke-direct {p1, v0}, Lyq0/k;-><init>(Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    iget-object v0, p0, Lzq0/b;->d:Ljavax/crypto/Cipher;

    .line 14
    .line 15
    iget-object p0, p0, Lzq0/b;->b:Lkotlin/jvm/internal/k;

    .line 16
    .line 17
    invoke-interface {p0, p1, v0}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    return-void
.end method
