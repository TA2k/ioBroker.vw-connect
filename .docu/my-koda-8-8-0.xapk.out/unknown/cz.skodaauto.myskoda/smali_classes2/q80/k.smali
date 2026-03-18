.class public final Lq80/k;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lq80/p;

.field public final b:Lbq0/r;


# direct methods
.method public constructor <init>(Lq80/p;Lbq0/r;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lq80/k;->a:Lq80/p;

    .line 5
    .line 6
    iput-object p2, p0, Lq80/k;->b:Lbq0/r;

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
    check-cast v1, Ljava/lang/Boolean;

    .line 5
    .line 6
    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 7
    .line 8
    .line 9
    move-result v1

    .line 10
    iget-object v2, p0, Lq80/k;->b:Lbq0/r;

    .line 11
    .line 12
    iget-object v2, v2, Lbq0/r;->a:Lbq0/h;

    .line 13
    .line 14
    check-cast v2, Lzp0/c;

    .line 15
    .line 16
    iput-boolean v1, v2, Lzp0/c;->e:Z

    .line 17
    .line 18
    iget-object p0, p0, Lq80/k;->a:Lq80/p;

    .line 19
    .line 20
    check-cast p0, Liy/b;

    .line 21
    .line 22
    sget-object v1, Lly/b;->e3:Lly/b;

    .line 23
    .line 24
    invoke-interface {p0, v1}, Ltl0/a;->a(Lul0/f;)V

    .line 25
    .line 26
    .line 27
    return-object v0
.end method
