.class public final synthetic Ltz/r2;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ltz/a3;

.field public final synthetic f:Z


# direct methods
.method public synthetic constructor <init>(Ltz/a3;ZI)V
    .locals 0

    .line 1
    iput p3, p0, Ltz/r2;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ltz/r2;->e:Ltz/a3;

    .line 4
    .line 5
    iput-boolean p2, p0, Ltz/r2;->f:Z

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
    iget v0, p0, Ltz/r2;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Llj0/e;

    .line 7
    .line 8
    iget-object v1, p0, Ltz/r2;->e:Ltz/a3;

    .line 9
    .line 10
    iget-object v1, v1, Ltz/a3;->w:Lij0/a;

    .line 11
    .line 12
    const v2, 0x7f120466

    .line 13
    .line 14
    .line 15
    check-cast v1, Ljj0/f;

    .line 16
    .line 17
    invoke-virtual {v1, v2}, Ljj0/f;->b(I)Ljava/lang/String;

    .line 18
    .line 19
    .line 20
    move-result-object v1

    .line 21
    iget-boolean p0, p0, Ltz/r2;->f:Z

    .line 22
    .line 23
    xor-int/lit8 p0, p0, 0x1

    .line 24
    .line 25
    invoke-direct {v0, v1, p0}, Llj0/e;-><init>(Ljava/lang/String;Z)V

    .line 26
    .line 27
    .line 28
    return-object v0

    .line 29
    :pswitch_0
    new-instance v0, Llj0/e;

    .line 30
    .line 31
    iget-object v1, p0, Ltz/r2;->e:Ltz/a3;

    .line 32
    .line 33
    iget-object v1, v1, Ltz/a3;->w:Lij0/a;

    .line 34
    .line 35
    const v2, 0x7f12047b

    .line 36
    .line 37
    .line 38
    check-cast v1, Ljj0/f;

    .line 39
    .line 40
    invoke-virtual {v1, v2}, Ljj0/f;->b(I)Ljava/lang/String;

    .line 41
    .line 42
    .line 43
    move-result-object v1

    .line 44
    iget-boolean p0, p0, Ltz/r2;->f:Z

    .line 45
    .line 46
    xor-int/lit8 p0, p0, 0x1

    .line 47
    .line 48
    invoke-direct {v0, v1, p0}, Llj0/e;-><init>(Ljava/lang/String;Z)V

    .line 49
    .line 50
    .line 51
    return-object v0

    .line 52
    :pswitch_1
    new-instance v0, Llj0/e;

    .line 53
    .line 54
    iget-object v1, p0, Ltz/r2;->e:Ltz/a3;

    .line 55
    .line 56
    iget-object v1, v1, Ltz/a3;->w:Lij0/a;

    .line 57
    .line 58
    const v2, 0x7f120465

    .line 59
    .line 60
    .line 61
    check-cast v1, Ljj0/f;

    .line 62
    .line 63
    invoke-virtual {v1, v2}, Ljj0/f;->b(I)Ljava/lang/String;

    .line 64
    .line 65
    .line 66
    move-result-object v1

    .line 67
    iget-boolean p0, p0, Ltz/r2;->f:Z

    .line 68
    .line 69
    xor-int/lit8 p0, p0, 0x1

    .line 70
    .line 71
    invoke-direct {v0, v1, p0}, Llj0/e;-><init>(Ljava/lang/String;Z)V

    .line 72
    .line 73
    .line 74
    return-object v0

    .line 75
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
