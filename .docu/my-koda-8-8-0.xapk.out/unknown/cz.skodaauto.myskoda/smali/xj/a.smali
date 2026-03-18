.class public final synthetic Lxj/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lzb/r0;


# direct methods
.method public synthetic constructor <init>(Lzb/r0;I)V
    .locals 0

    .line 1
    iput p2, p0, Lxj/a;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lxj/a;->e:Lzb/r0;

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
    iget v0, p0, Lxj/a;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lxj/a;->e:Lzb/r0;

    .line 7
    .line 8
    iget v0, p0, Lzb/r0;->a:I

    .line 9
    .line 10
    const/4 v1, 0x1

    .line 11
    if-le v0, v1, :cond_0

    .line 12
    .line 13
    iget-object p0, p0, Lzb/r0;->b:Ll2/j1;

    .line 14
    .line 15
    sub-int/2addr v0, v1

    .line 16
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    invoke-virtual {p0, v0}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 21
    .line 22
    .line 23
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 24
    .line 25
    return-object p0

    .line 26
    :pswitch_0
    iget-object p0, p0, Lxj/a;->e:Lzb/r0;

    .line 27
    .line 28
    iget-object v0, p0, Lzb/r0;->b:Ll2/j1;

    .line 29
    .line 30
    invoke-virtual {v0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 31
    .line 32
    .line 33
    move-result-object v1

    .line 34
    check-cast v1, Ljava/lang/Number;

    .line 35
    .line 36
    invoke-virtual {v1}, Ljava/lang/Number;->intValue()I

    .line 37
    .line 38
    .line 39
    move-result v1

    .line 40
    iget p0, p0, Lzb/r0;->a:I

    .line 41
    .line 42
    if-ge v1, p0, :cond_1

    .line 43
    .line 44
    invoke-virtual {v0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    check-cast p0, Ljava/lang/Number;

    .line 49
    .line 50
    invoke-virtual {p0}, Ljava/lang/Number;->intValue()I

    .line 51
    .line 52
    .line 53
    move-result p0

    .line 54
    add-int/lit8 p0, p0, 0x1

    .line 55
    .line 56
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 57
    .line 58
    .line 59
    move-result-object p0

    .line 60
    invoke-virtual {v0, p0}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 61
    .line 62
    .line 63
    :cond_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 64
    .line 65
    return-object p0

    .line 66
    nop

    .line 67
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
