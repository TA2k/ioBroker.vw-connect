.class public final Lf40/q0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lf40/d1;


# direct methods
.method public constructor <init>(Lf40/d1;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lf40/q0;->a:Lf40/d1;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 3

    .line 1
    iget-object p0, p0, Lf40/q0;->a:Lf40/d1;

    .line 2
    .line 3
    check-cast p0, Ld40/f;

    .line 4
    .line 5
    iget-object v0, p0, Ld40/f;->c:Lyy0/c2;

    .line 6
    .line 7
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 8
    .line 9
    .line 10
    const/4 v1, 0x0

    .line 11
    sget-object v2, Lne0/d;->a:Lne0/d;

    .line 12
    .line 13
    invoke-virtual {v0, v1, v2}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 14
    .line 15
    .line 16
    iget-object p0, p0, Ld40/f;->a:Lwe0/a;

    .line 17
    .line 18
    check-cast p0, Lwe0/c;

    .line 19
    .line 20
    invoke-virtual {p0}, Lwe0/c;->a()V

    .line 21
    .line 22
    .line 23
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 24
    .line 25
    return-object p0
.end method
