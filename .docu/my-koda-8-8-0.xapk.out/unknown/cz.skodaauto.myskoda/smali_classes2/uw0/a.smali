.class public final Luw0/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:[B

.field public final b:[B

.field public final c:[B


# direct methods
.method public constructor <init>(Ljava/nio/charset/Charset;)V
    .locals 1

    .line 1
    const-string v0, "charset"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    const-string v0, "["

    .line 10
    .line 11
    invoke-static {v0, p1}, Ljp/ib;->c(Ljava/lang/String;Ljava/nio/charset/Charset;)[B

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    iput-object v0, p0, Luw0/a;->a:[B

    .line 16
    .line 17
    const-string v0, "]"

    .line 18
    .line 19
    invoke-static {v0, p1}, Ljp/ib;->c(Ljava/lang/String;Ljava/nio/charset/Charset;)[B

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    iput-object v0, p0, Luw0/a;->b:[B

    .line 24
    .line 25
    const-string v0, ","

    .line 26
    .line 27
    invoke-static {v0, p1}, Ljp/ib;->c(Ljava/lang/String;Ljava/nio/charset/Charset;)[B

    .line 28
    .line 29
    .line 30
    move-result-object p1

    .line 31
    iput-object p1, p0, Luw0/a;->c:[B

    .line 32
    .line 33
    return-void
.end method
