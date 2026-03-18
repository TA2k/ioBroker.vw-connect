.class public final Lf40/o0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lf40/a1;


# direct methods
.method public constructor <init>(Lf40/a1;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lf40/o0;->a:Lf40/a1;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 3

    .line 1
    iget-object p0, p0, Lf40/o0;->a:Lf40/a1;

    .line 2
    .line 3
    check-cast p0, Ld40/c;

    .line 4
    .line 5
    iget-object v0, p0, Ld40/c;->c:Lyy0/c2;

    .line 6
    .line 7
    :cond_0
    invoke-virtual {v0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    move-result-object v1

    .line 11
    move-object v2, v1

    .line 12
    check-cast v2, Lne0/s;

    .line 13
    .line 14
    sget-object v2, Lne0/d;->a:Lne0/d;

    .line 15
    .line 16
    invoke-virtual {v0, v1, v2}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 17
    .line 18
    .line 19
    move-result v1

    .line 20
    if-eqz v1, :cond_0

    .line 21
    .line 22
    iget-object p0, p0, Ld40/c;->a:Lwe0/a;

    .line 23
    .line 24
    check-cast p0, Lwe0/c;

    .line 25
    .line 26
    invoke-virtual {p0}, Lwe0/c;->a()V

    .line 27
    .line 28
    .line 29
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    return-object p0
.end method
