.class public final synthetic Lmg/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/p;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/String;

.field public final synthetic f:Lxh/e;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/String;Lxh/e;I)V
    .locals 0

    .line 1
    iput p3, p0, Lmg/e;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lmg/e;->e:Ljava/lang/String;

    .line 4
    .line 5
    iput-object p2, p0, Lmg/e;->f:Lxh/e;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    .line 1
    iget v0, p0, Lmg/e;->d:I

    .line 2
    .line 3
    check-cast p1, Lb1/n;

    .line 4
    .line 5
    check-cast p2, Lz9/k;

    .line 6
    .line 7
    check-cast p3, Ll2/o;

    .line 8
    .line 9
    check-cast p4, Ljava/lang/Integer;

    .line 10
    .line 11
    packed-switch v0, :pswitch_data_0

    .line 12
    .line 13
    .line 14
    const-string v0, "$this$composable"

    .line 15
    .line 16
    const-string v1, "it"

    .line 17
    .line 18
    invoke-static {p4, p1, v0, p2, v1}, Lz9/c;->c(Ljava/lang/Integer;Lb1/n;Ljava/lang/String;Lz9/k;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    const/4 p1, 0x0

    .line 22
    iget-object p2, p0, Lmg/e;->e:Ljava/lang/String;

    .line 23
    .line 24
    iget-object p0, p0, Lmg/e;->f:Lxh/e;

    .line 25
    .line 26
    invoke-static {p2, p0, p3, p1}, Lkp/y7;->c(Ljava/lang/String;Lxh/e;Ll2/o;I)V

    .line 27
    .line 28
    .line 29
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    return-object p0

    .line 32
    :pswitch_0
    const-string v0, "$this$composable"

    .line 33
    .line 34
    const-string v1, "it"

    .line 35
    .line 36
    invoke-static {p4, p1, v0, p2, v1}, Lz9/c;->c(Ljava/lang/Integer;Lb1/n;Ljava/lang/String;Lz9/k;Ljava/lang/String;)V

    .line 37
    .line 38
    .line 39
    const/4 p1, 0x0

    .line 40
    iget-object p2, p0, Lmg/e;->e:Ljava/lang/String;

    .line 41
    .line 42
    iget-object p0, p0, Lmg/e;->f:Lxh/e;

    .line 43
    .line 44
    invoke-static {p2, p0, p3, p1}, Lkp/x7;->a(Ljava/lang/String;Lxh/e;Ll2/o;I)V

    .line 45
    .line 46
    .line 47
    goto :goto_0

    .line 48
    nop

    .line 49
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
