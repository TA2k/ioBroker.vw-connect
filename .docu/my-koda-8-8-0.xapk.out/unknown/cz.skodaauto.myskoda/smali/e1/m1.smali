.class public final synthetic Le1/m1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Le1/n1;


# direct methods
.method public synthetic constructor <init>(Le1/n1;I)V
    .locals 0

    .line 1
    iput p2, p0, Le1/m1;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Le1/m1;->e:Le1/n1;

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
    .locals 1

    .line 1
    iget v0, p0, Le1/m1;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Le1/m1;->e:Le1/n1;

    .line 7
    .line 8
    iget-object p0, p0, Le1/n1;->d:Ll2/g1;

    .line 9
    .line 10
    invoke-virtual {p0}, Ll2/g1;->o()I

    .line 11
    .line 12
    .line 13
    move-result p0

    .line 14
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    return-object p0

    .line 19
    :pswitch_0
    iget-object p0, p0, Le1/m1;->e:Le1/n1;

    .line 20
    .line 21
    iget-object p0, p0, Le1/n1;->a:Ll2/g1;

    .line 22
    .line 23
    invoke-virtual {p0}, Ll2/g1;->o()I

    .line 24
    .line 25
    .line 26
    move-result p0

    .line 27
    if-lez p0, :cond_0

    .line 28
    .line 29
    const/4 p0, 0x1

    .line 30
    goto :goto_0

    .line 31
    :cond_0
    const/4 p0, 0x0

    .line 32
    :goto_0
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 33
    .line 34
    .line 35
    move-result-object p0

    .line 36
    return-object p0

    .line 37
    :pswitch_1
    iget-object p0, p0, Le1/m1;->e:Le1/n1;

    .line 38
    .line 39
    iget-object v0, p0, Le1/n1;->a:Ll2/g1;

    .line 40
    .line 41
    invoke-virtual {v0}, Ll2/g1;->o()I

    .line 42
    .line 43
    .line 44
    move-result v0

    .line 45
    iget-object p0, p0, Le1/n1;->d:Ll2/g1;

    .line 46
    .line 47
    invoke-virtual {p0}, Ll2/g1;->o()I

    .line 48
    .line 49
    .line 50
    move-result p0

    .line 51
    if-ge v0, p0, :cond_1

    .line 52
    .line 53
    const/4 p0, 0x1

    .line 54
    goto :goto_1

    .line 55
    :cond_1
    const/4 p0, 0x0

    .line 56
    :goto_1
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 57
    .line 58
    .line 59
    move-result-object p0

    .line 60
    return-object p0

    .line 61
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
