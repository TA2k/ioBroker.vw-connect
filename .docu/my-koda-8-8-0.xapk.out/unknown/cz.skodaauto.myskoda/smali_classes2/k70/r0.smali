.class public final Lk70/r0;
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
    iput-object p1, p0, Lk70/r0;->a:Lk70/a1;

    .line 5
    .line 6
    iput-object p2, p0, Lk70/r0;->b:Lk70/v;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 4

    .line 1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 2
    .line 3
    move-object v1, v0

    .line 4
    check-cast v1, Ll70/d;

    .line 5
    .line 6
    iget-object v2, v1, Ll70/d;->d:Ll70/h;

    .line 7
    .line 8
    iget-object v3, p0, Lk70/r0;->b:Lk70/v;

    .line 9
    .line 10
    check-cast v3, Li70/b;

    .line 11
    .line 12
    iput-object v2, v3, Li70/b;->b:Ll70/h;

    .line 13
    .line 14
    iput-object v1, v3, Li70/b;->a:Ll70/d;

    .line 15
    .line 16
    iget-object p0, p0, Lk70/r0;->a:Lk70/a1;

    .line 17
    .line 18
    check-cast p0, Liy/b;

    .line 19
    .line 20
    sget-object v1, Lly/b;->T3:Lly/b;

    .line 21
    .line 22
    invoke-interface {p0, v1}, Ltl0/a;->a(Lul0/f;)V

    .line 23
    .line 24
    .line 25
    return-object v0
.end method
