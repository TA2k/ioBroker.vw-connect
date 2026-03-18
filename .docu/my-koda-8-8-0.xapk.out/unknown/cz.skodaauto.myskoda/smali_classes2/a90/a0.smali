.class public final La90/a0;
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
    iput-object p1, p0, La90/a0;->a:La90/q;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 1

    .line 1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 2
    .line 3
    check-cast v0, Lb90/d;

    .line 4
    .line 5
    sget-object v0, Lb90/d;->f:Lb90/d;

    .line 6
    .line 7
    iget-object p0, p0, La90/a0;->a:La90/q;

    .line 8
    .line 9
    check-cast p0, Ly80/a;

    .line 10
    .line 11
    iget-object p0, p0, Ly80/a;->j:Ljava/lang/Object;

    .line 12
    .line 13
    invoke-interface {p0, v0}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 14
    .line 15
    .line 16
    move-result p0

    .line 17
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    return-object p0
.end method
