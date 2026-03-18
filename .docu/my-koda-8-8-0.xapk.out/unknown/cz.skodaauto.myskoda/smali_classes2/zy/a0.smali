.class public final Lzy/a0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lzy/m;

.field public final b:Lpp0/l1;


# direct methods
.method public constructor <init>(Lzy/m;Lpp0/l1;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lzy/a0;->a:Lzy/m;

    .line 5
    .line 6
    iput-object p2, p0, Lzy/a0;->b:Lpp0/l1;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 3

    .line 1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 2
    .line 3
    move-object v1, v0

    .line 4
    check-cast v1, Lqp0/o;

    .line 5
    .line 6
    iget-object v2, p0, Lzy/a0;->b:Lpp0/l1;

    .line 7
    .line 8
    invoke-virtual {v2, v1}, Lpp0/l1;->a(Lqp0/o;)V

    .line 9
    .line 10
    .line 11
    iget-object p0, p0, Lzy/a0;->a:Lzy/m;

    .line 12
    .line 13
    check-cast p0, Liy/b;

    .line 14
    .line 15
    sget-object v1, Lly/b;->V1:Lly/b;

    .line 16
    .line 17
    invoke-interface {p0, v1}, Ltl0/a;->a(Lul0/f;)V

    .line 18
    .line 19
    .line 20
    return-object v0
.end method
