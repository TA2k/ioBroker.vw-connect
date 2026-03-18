.class public final Lw70/d0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lbq0/u;

.field public final b:Lw70/q0;


# direct methods
.method public constructor <init>(Lbq0/u;Lw70/q0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lw70/d0;->a:Lbq0/u;

    .line 5
    .line 6
    iput-object p2, p0, Lw70/d0;->b:Lw70/q0;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 2

    .line 1
    sget-object v0, Lcq0/y;->d:Lcq0/y;

    .line 2
    .line 3
    iget-object v1, p0, Lw70/d0;->a:Lbq0/u;

    .line 4
    .line 5
    iget-object v1, v1, Lbq0/u;->a:Lbq0/h;

    .line 6
    .line 7
    check-cast v1, Lzp0/c;

    .line 8
    .line 9
    iput-object v0, v1, Lzp0/c;->k:Lcq0/y;

    .line 10
    .line 11
    iget-object p0, p0, Lw70/d0;->b:Lw70/q0;

    .line 12
    .line 13
    check-cast p0, Liy/b;

    .line 14
    .line 15
    sget-object v0, Lly/b;->f3:Lly/b;

    .line 16
    .line 17
    invoke-interface {p0, v0}, Ltl0/a;->a(Lul0/f;)V

    .line 18
    .line 19
    .line 20
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 21
    .line 22
    return-object p0
.end method
