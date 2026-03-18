.class public final synthetic Lxj/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lay0/k;

.field public final synthetic f:Lzc/a;


# direct methods
.method public synthetic constructor <init>(Lay0/k;Lzc/a;I)V
    .locals 0

    .line 1
    iput p3, p0, Lxj/d;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lxj/d;->e:Lay0/k;

    .line 4
    .line 5
    iput-object p2, p0, Lxj/d;->f:Lzc/a;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 3

    .line 1
    iget v0, p0, Lxj/d;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Lzc/b;

    .line 7
    .line 8
    iget-object v1, p0, Lxj/d;->f:Lzc/a;

    .line 9
    .line 10
    iget-boolean v2, v1, Lzc/a;->d:Z

    .line 11
    .line 12
    iget-object v1, v1, Lzc/a;->c:Ljava/lang/String;

    .line 13
    .line 14
    invoke-direct {v0, v2, v1}, Lzc/b;-><init>(ZLjava/lang/String;)V

    .line 15
    .line 16
    .line 17
    iget-object p0, p0, Lxj/d;->e:Lay0/k;

    .line 18
    .line 19
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 23
    .line 24
    return-object p0

    .line 25
    :pswitch_0
    new-instance v0, Lzc/d;

    .line 26
    .line 27
    iget-object v1, p0, Lxj/d;->f:Lzc/a;

    .line 28
    .line 29
    iget-object v1, v1, Lzc/a;->b:Ljava/lang/String;

    .line 30
    .line 31
    invoke-direct {v0, v1}, Lzc/d;-><init>(Ljava/lang/String;)V

    .line 32
    .line 33
    .line 34
    iget-object p0, p0, Lxj/d;->e:Lay0/k;

    .line 35
    .line 36
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 37
    .line 38
    .line 39
    goto :goto_0

    .line 40
    :pswitch_1
    new-instance v0, Lzc/b;

    .line 41
    .line 42
    iget-object v1, p0, Lxj/d;->f:Lzc/a;

    .line 43
    .line 44
    iget-boolean v2, v1, Lzc/a;->d:Z

    .line 45
    .line 46
    iget-object v1, v1, Lzc/a;->c:Ljava/lang/String;

    .line 47
    .line 48
    invoke-direct {v0, v2, v1}, Lzc/b;-><init>(ZLjava/lang/String;)V

    .line 49
    .line 50
    .line 51
    iget-object p0, p0, Lxj/d;->e:Lay0/k;

    .line 52
    .line 53
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 54
    .line 55
    .line 56
    goto :goto_0

    .line 57
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
