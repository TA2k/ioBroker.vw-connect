.class public final Ll50/y;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lbq0/t;

.field public final b:Ll50/k;


# direct methods
.method public constructor <init>(Lbq0/t;Ll50/k;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ll50/y;->a:Lbq0/t;

    .line 5
    .line 6
    iput-object p2, p0, Ll50/y;->b:Ll50/k;

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
    check-cast v1, Ljava/lang/String;

    .line 5
    .line 6
    new-instance v2, Lcq0/p;

    .line 7
    .line 8
    invoke-direct {v2, v1}, Lcq0/p;-><init>(Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    iget-object v1, p0, Ll50/y;->a:Lbq0/t;

    .line 12
    .line 13
    iget-object v1, v1, Lbq0/t;->a:Lbq0/h;

    .line 14
    .line 15
    check-cast v1, Lzp0/c;

    .line 16
    .line 17
    iput-object v2, v1, Lzp0/c;->f:Lcq0/q;

    .line 18
    .line 19
    iget-object p0, p0, Ll50/y;->b:Ll50/k;

    .line 20
    .line 21
    check-cast p0, Liy/b;

    .line 22
    .line 23
    sget-object v1, Lly/b;->j3:Lly/b;

    .line 24
    .line 25
    invoke-interface {p0, v1}, Ltl0/a;->a(Lul0/f;)V

    .line 26
    .line 27
    .line 28
    return-object v0
.end method
