.class public final Lrs/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lxo/f;
.implements Llo/l;


# instance fields
.field public final d:Ljava/lang/String;

.field public final e:I


# direct methods
.method public constructor <init>(ILjava/lang/String;)V
    .locals 0

    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    iput p1, p0, Lrs/a;->e:I

    .line 5
    iput-object p2, p0, Lrs/a;->d:Ljava/lang/String;

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/String;I)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lrs/a;->d:Ljava/lang/String;

    iput p2, p0, Lrs/a;->e:I

    return-void
.end method

.method public constructor <init>(Lxo/c;Ljava/lang/String;I)V
    .locals 0

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p2, p0, Lrs/a;->d:Ljava/lang/String;

    iput p3, p0, Lrs/a;->e:I

    return-void
.end method


# virtual methods
.method public Q()V
    .locals 0

    .line 1
    return-void
.end method

.method public c(Lj51/b;)V
    .locals 2

    .line 1
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2
    .line 3
    .line 4
    const-string v0, "digitalKeyId"

    .line 5
    .line 6
    iget-object v1, p0, Lrs/a;->d:Ljava/lang/String;

    .line 7
    .line 8
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    iget-object p1, p1, Lj51/b;->a:Lxy0/x;

    .line 12
    .line 13
    new-instance v0, Lk51/f;

    .line 14
    .line 15
    iget p0, p0, Lrs/a;->e:I

    .line 16
    .line 17
    invoke-direct {v0, v1, p0}, Lk51/f;-><init>(Ljava/lang/String;I)V

    .line 18
    .line 19
    .line 20
    check-cast p1, Lxy0/w;

    .line 21
    .line 22
    invoke-virtual {p1, v0}, Lxy0/w;->e(Ljava/lang/Object;)Ljava/lang/Object;

    .line 23
    .line 24
    .line 25
    return-void
.end method

.method public q(Ljava/lang/Object;)V
    .locals 2

    .line 1
    check-cast p1, Lj51/a;

    .line 2
    .line 3
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    const-string v0, "digitalKeyId"

    .line 7
    .line 8
    iget-object v1, p0, Lrs/a;->d:Ljava/lang/String;

    .line 9
    .line 10
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    iget-object p1, p1, Lj51/a;->a:Lxy0/x;

    .line 14
    .line 15
    new-instance v0, Lj51/c;

    .line 16
    .line 17
    iget p0, p0, Lrs/a;->e:I

    .line 18
    .line 19
    invoke-direct {v0, v1, p0}, Lj51/c;-><init>(Ljava/lang/String;I)V

    .line 20
    .line 21
    .line 22
    check-cast p1, Lxy0/w;

    .line 23
    .line 24
    invoke-virtual {p1, v0}, Lxy0/w;->e(Ljava/lang/Object;)Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    return-void
.end method
