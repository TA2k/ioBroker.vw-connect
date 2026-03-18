.class public final synthetic Lny/z;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lz9/y;

.field public final synthetic f:Lay0/k;


# direct methods
.method public synthetic constructor <init>(Lz9/y;Lay0/k;I)V
    .locals 0

    .line 1
    iput p3, p0, Lny/z;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lny/z;->e:Lz9/y;

    .line 4
    .line 5
    iput-object p2, p0, Lny/z;->f:Lay0/k;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    .line 1
    iget v0, p0, Lny/z;->d:I

    .line 2
    .line 3
    check-cast p1, Landroidx/compose/runtime/DisposableEffectScope;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    const-string v0, "$this$DisposableEffect"

    .line 9
    .line 10
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    new-instance p1, Lny/b0;

    .line 14
    .line 15
    const/4 v0, 0x0

    .line 16
    iget-object v1, p0, Lny/z;->f:Lay0/k;

    .line 17
    .line 18
    invoke-direct {p1, v0, v1}, Lny/b0;-><init>(ILay0/k;)V

    .line 19
    .line 20
    .line 21
    iget-object p0, p0, Lny/z;->e:Lz9/y;

    .line 22
    .line 23
    invoke-virtual {p0, p1}, Lz9/y;->a(Lny/b0;)V

    .line 24
    .line 25
    .line 26
    new-instance v0, Laa/t;

    .line 27
    .line 28
    const/16 v1, 0xb

    .line 29
    .line 30
    invoke-direct {v0, v1, p0, p1}, Laa/t;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 31
    .line 32
    .line 33
    return-object v0

    .line 34
    :pswitch_0
    const-string v0, "$this$DisposableEffect"

    .line 35
    .line 36
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 37
    .line 38
    .line 39
    new-instance p1, Lny/b0;

    .line 40
    .line 41
    const/4 v0, 0x1

    .line 42
    iget-object v1, p0, Lny/z;->f:Lay0/k;

    .line 43
    .line 44
    invoke-direct {p1, v0, v1}, Lny/b0;-><init>(ILay0/k;)V

    .line 45
    .line 46
    .line 47
    iget-object p0, p0, Lny/z;->e:Lz9/y;

    .line 48
    .line 49
    invoke-virtual {p0, p1}, Lz9/y;->a(Lny/b0;)V

    .line 50
    .line 51
    .line 52
    new-instance v0, Laa/t;

    .line 53
    .line 54
    const/16 v1, 0xa

    .line 55
    .line 56
    invoke-direct {v0, v1, p0, p1}, Laa/t;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 57
    .line 58
    .line 59
    return-object v0

    .line 60
    nop

    .line 61
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
