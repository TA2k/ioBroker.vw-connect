.class public final Lz90/r;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lbn0/g;

.field public final b:Llb0/d;

.field public final c:Lqd0/u;


# direct methods
.method public constructor <init>(Lbn0/g;Llb0/d;Lqd0/u;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lz90/r;->a:Lbn0/g;

    .line 5
    .line 6
    iput-object p2, p0, Lz90/r;->b:Llb0/d;

    .line 7
    .line 8
    iput-object p3, p0, Lz90/r;->c:Lqd0/u;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 4

    .line 1
    new-instance v0, Lbn0/c;

    .line 2
    .line 3
    sget-object v1, Laa0/h;->d:[Laa0/h;

    .line 4
    .line 5
    const-string v1, "apply-backup"

    .line 6
    .line 7
    const-string v2, "vehicle-services-backup"

    .line 8
    .line 9
    invoke-direct {v0, v2, v1}, Lbn0/c;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    iget-object v1, p0, Lz90/r;->a:Lbn0/g;

    .line 13
    .line 14
    invoke-virtual {v1, v0}, Lbn0/g;->a(Lbn0/c;)Lzy0/j;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    new-instance v1, Lus0/a;

    .line 19
    .line 20
    const/4 v2, 0x0

    .line 21
    const/4 v3, 0x7

    .line 22
    invoke-direct {v1, p0, v2, v3}, Lus0/a;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 23
    .line 24
    .line 25
    new-instance p0, Lac/l;

    .line 26
    .line 27
    invoke-direct {p0, v0, v1}, Lac/l;-><init>(Lzy0/j;Lay0/k;)V

    .line 28
    .line 29
    .line 30
    return-object p0
.end method
