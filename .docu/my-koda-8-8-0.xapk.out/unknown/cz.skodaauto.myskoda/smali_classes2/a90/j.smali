.class public final La90/j;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:La90/q;


# direct methods
.method public constructor <init>(La90/q;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, La90/j;->a:La90/q;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a(Lb90/d;)Lb90/e;
    .locals 2

    .line 1
    new-instance v0, Lb90/e;

    .line 2
    .line 3
    iget-object p0, p0, La90/j;->a:La90/q;

    .line 4
    .line 5
    check-cast p0, Ly80/a;

    .line 6
    .line 7
    iget-object v1, p0, Ly80/a;->j:Ljava/lang/Object;

    .line 8
    .line 9
    invoke-interface {v1, p1}, Ljava/util/List;->indexOf(Ljava/lang/Object;)I

    .line 10
    .line 11
    .line 12
    move-result p1

    .line 13
    add-int/lit8 p1, p1, 0x1

    .line 14
    .line 15
    iget-object p0, p0, Ly80/a;->j:Ljava/lang/Object;

    .line 16
    .line 17
    invoke-interface {p0}, Ljava/util/List;->size()I

    .line 18
    .line 19
    .line 20
    move-result p0

    .line 21
    invoke-direct {v0, p1, p0}, Lb90/e;-><init>(II)V

    .line 22
    .line 23
    .line 24
    return-object v0
.end method

.method public final bridge synthetic invoke()Ljava/lang/Object;
    .locals 1

    .line 1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 2
    .line 3
    check-cast v0, Lb90/d;

    .line 4
    .line 5
    invoke-virtual {p0, v0}, La90/j;->a(Lb90/d;)Lb90/e;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method
