.class public final Lf40/k4;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lf40/c1;


# direct methods
.method public constructor <init>(Lf40/c1;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lf40/k4;->a:Lf40/c1;

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
    check-cast v1, Lg40/u0;

    .line 5
    .line 6
    sget-object v1, Lg40/u0;->e:Lg40/u0;

    .line 7
    .line 8
    iget-object p0, p0, Lf40/k4;->a:Lf40/c1;

    .line 9
    .line 10
    check-cast p0, Ld40/e;

    .line 11
    .line 12
    iget-object p0, p0, Ld40/e;->g:Lyy0/q1;

    .line 13
    .line 14
    invoke-virtual {p0, v1}, Lyy0/q1;->a(Ljava/lang/Object;)Z

    .line 15
    .line 16
    .line 17
    return-object v0
.end method
