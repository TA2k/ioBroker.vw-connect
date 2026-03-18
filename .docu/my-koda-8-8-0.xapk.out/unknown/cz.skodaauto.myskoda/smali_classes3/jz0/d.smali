.class public final Ljz0/d;
.super Ljz0/f;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final b:Lkz0/c;

.field public final c:Llz0/n;


# direct methods
.method public constructor <init>(Ljava/util/List;)V
    .locals 1

    .line 1
    const-string v0, "formats"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0, p1}, Ljz0/f;-><init>(Ljava/util/List;)V

    .line 7
    .line 8
    .line 9
    invoke-super {p0}, Ljz0/f;->a()Lkz0/c;

    .line 10
    .line 11
    .line 12
    move-result-object p1

    .line 13
    iput-object p1, p0, Ljz0/d;->b:Lkz0/c;

    .line 14
    .line 15
    invoke-super {p0}, Ljz0/f;->b()Llz0/n;

    .line 16
    .line 17
    .line 18
    move-result-object p1

    .line 19
    iput-object p1, p0, Ljz0/d;->c:Llz0/n;

    .line 20
    .line 21
    return-void
.end method


# virtual methods
.method public final a()Lkz0/c;
    .locals 0

    .line 1
    iget-object p0, p0, Ljz0/d;->b:Lkz0/c;

    .line 2
    .line 3
    return-object p0
.end method

.method public final b()Llz0/n;
    .locals 0

    .line 1
    iget-object p0, p0, Ljz0/d;->c:Llz0/n;

    .line 2
    .line 3
    return-object p0
.end method
