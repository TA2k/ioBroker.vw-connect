.class public final Lf40/q1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lf40/f1;


# direct methods
.method public constructor <init>(Lf40/f1;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lf40/q1;->a:Lf40/f1;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 2

    .line 1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 2
    .line 3
    move-object v1, v0

    .line 4
    check-cast v1, Lf40/p1;

    .line 5
    .line 6
    iget-object p0, p0, Lf40/q1;->a:Lf40/f1;

    .line 7
    .line 8
    check-cast p0, Liy/b;

    .line 9
    .line 10
    sget-object v1, Lly/b;->F1:Lly/b;

    .line 11
    .line 12
    invoke-interface {p0, v1}, Ltl0/a;->a(Lul0/f;)V

    .line 13
    .line 14
    .line 15
    return-object v0
.end method
