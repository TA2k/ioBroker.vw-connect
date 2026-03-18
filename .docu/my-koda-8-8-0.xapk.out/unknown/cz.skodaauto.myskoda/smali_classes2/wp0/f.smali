.class public final Lwp0/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lzo0/n;


# direct methods
.method public constructor <init>(Lzo0/n;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lwp0/f;->a:Lzo0/n;

    .line 5
    .line 6
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
    check-cast v1, Lap0/e;

    .line 5
    .line 6
    iget-object p0, p0, Lwp0/f;->a:Lzo0/n;

    .line 7
    .line 8
    check-cast p0, Lup0/a;

    .line 9
    .line 10
    new-instance v2, Lup0/c;

    .line 11
    .line 12
    invoke-direct {v2, v1}, Lup0/c;-><init>(Lap0/e;)V

    .line 13
    .line 14
    .line 15
    iget-object p0, p0, Lup0/a;->a:Lyy0/q1;

    .line 16
    .line 17
    invoke-virtual {p0, v2}, Lyy0/q1;->a(Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    return-object v0
.end method
