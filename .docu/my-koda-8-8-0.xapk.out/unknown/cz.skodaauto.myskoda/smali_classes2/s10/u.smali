.class public final synthetic Ls10/u;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ls10/y;


# direct methods
.method public synthetic constructor <init>(Ls10/y;I)V
    .locals 0

    .line 1
    iput p2, p0, Ls10/u;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ls10/u;->e:Ls10/y;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 2

    .line 1
    iget v0, p0, Ls10/u;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Llj0/a;

    .line 7
    .line 8
    iget-object p0, p0, Ls10/u;->e:Ls10/y;

    .line 9
    .line 10
    iget-object p0, p0, Ls10/y;->m:Lij0/a;

    .line 11
    .line 12
    const v1, 0x7f120373

    .line 13
    .line 14
    .line 15
    check-cast p0, Ljj0/f;

    .line 16
    .line 17
    invoke-virtual {p0, v1}, Ljj0/f;->b(I)Ljava/lang/String;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    invoke-direct {v0, p0}, Llj0/a;-><init>(Ljava/lang/String;)V

    .line 22
    .line 23
    .line 24
    return-object v0

    .line 25
    :pswitch_0
    new-instance v0, Llj0/a;

    .line 26
    .line 27
    iget-object p0, p0, Ls10/u;->e:Ls10/y;

    .line 28
    .line 29
    iget-object p0, p0, Ls10/y;->m:Lij0/a;

    .line 30
    .line 31
    const v1, 0x7f120f3d

    .line 32
    .line 33
    .line 34
    check-cast p0, Ljj0/f;

    .line 35
    .line 36
    invoke-virtual {p0, v1}, Ljj0/f;->b(I)Ljava/lang/String;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    invoke-direct {v0, p0}, Llj0/a;-><init>(Ljava/lang/String;)V

    .line 41
    .line 42
    .line 43
    return-object v0

    .line 44
    :pswitch_1
    new-instance v0, Llj0/a;

    .line 45
    .line 46
    iget-object p0, p0, Ls10/u;->e:Ls10/y;

    .line 47
    .line 48
    iget-object p0, p0, Ls10/y;->m:Lij0/a;

    .line 49
    .line 50
    const v1, 0x7f12037f

    .line 51
    .line 52
    .line 53
    check-cast p0, Ljj0/f;

    .line 54
    .line 55
    invoke-virtual {p0, v1}, Ljj0/f;->b(I)Ljava/lang/String;

    .line 56
    .line 57
    .line 58
    move-result-object p0

    .line 59
    invoke-direct {v0, p0}, Llj0/a;-><init>(Ljava/lang/String;)V

    .line 60
    .line 61
    .line 62
    return-object v0

    .line 63
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
