.class public final Lf50/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lf50/n;

.field public final b:Lf50/p;


# direct methods
.method public constructor <init>(Lf50/n;Lf50/p;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lf50/i;->a:Lf50/n;

    .line 5
    .line 6
    iput-object p2, p0, Lf50/i;->b:Lf50/p;

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
    check-cast v1, Lqp0/e;

    .line 5
    .line 6
    iget-object v2, p0, Lf50/i;->b:Lf50/p;

    .line 7
    .line 8
    iget-object v2, v2, Lf50/p;->a:Lf50/d;

    .line 9
    .line 10
    check-cast v2, Lc50/a;

    .line 11
    .line 12
    iput-object v1, v2, Lc50/a;->a:Lqp0/e;

    .line 13
    .line 14
    iget-object p0, p0, Lf50/i;->a:Lf50/n;

    .line 15
    .line 16
    check-cast p0, Liy/b;

    .line 17
    .line 18
    sget-object v1, Lly/b;->X1:Lly/b;

    .line 19
    .line 20
    invoke-interface {p0, v1}, Ltl0/a;->a(Lul0/f;)V

    .line 21
    .line 22
    .line 23
    return-object v0
.end method
