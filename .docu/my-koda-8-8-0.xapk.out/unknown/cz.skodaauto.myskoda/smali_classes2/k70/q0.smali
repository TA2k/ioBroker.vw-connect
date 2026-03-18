.class public final Lk70/q0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lk70/a1;

.field public final b:Lk70/v;


# direct methods
.method public constructor <init>(Lk70/a1;Lk70/v;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lk70/q0;->a:Lk70/a1;

    .line 5
    .line 6
    iput-object p2, p0, Lk70/q0;->b:Lk70/v;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a(Ll70/h;)V
    .locals 1

    .line 1
    const-string v0, "input"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lk70/q0;->b:Lk70/v;

    .line 7
    .line 8
    check-cast v0, Li70/b;

    .line 9
    .line 10
    iput-object p1, v0, Li70/b;->b:Ll70/h;

    .line 11
    .line 12
    const/4 p1, 0x0

    .line 13
    iput-object p1, v0, Li70/b;->a:Ll70/d;

    .line 14
    .line 15
    iget-object p0, p0, Lk70/q0;->a:Lk70/a1;

    .line 16
    .line 17
    check-cast p0, Liy/b;

    .line 18
    .line 19
    sget-object p1, Lly/b;->T3:Lly/b;

    .line 20
    .line 21
    invoke-interface {p0, p1}, Ltl0/a;->a(Lul0/f;)V

    .line 22
    .line 23
    .line 24
    return-void
.end method

.method public final bridge synthetic invoke()Ljava/lang/Object;
    .locals 2

    .line 1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 2
    .line 3
    move-object v1, v0

    .line 4
    check-cast v1, Ll70/h;

    .line 5
    .line 6
    invoke-virtual {p0, v1}, Lk70/q0;->a(Ll70/h;)V

    .line 7
    .line 8
    .line 9
    return-object v0
.end method
