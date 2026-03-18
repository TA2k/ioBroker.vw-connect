.class public final synthetic Lqf/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/p;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/String;

.field public final synthetic f:Lyj/b;

.field public final synthetic g:Ll2/b1;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/String;Lyj/b;Ll2/b1;I)V
    .locals 0

    .line 1
    iput p4, p0, Lqf/b;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lqf/b;->e:Ljava/lang/String;

    .line 4
    .line 5
    iput-object p2, p0, Lqf/b;->f:Lyj/b;

    .line 6
    .line 7
    iput-object p3, p0, Lqf/b;->g:Ll2/b1;

    .line 8
    .line 9
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 10
    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    .line 1
    iget v0, p0, Lqf/b;->d:I

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
    iget-object p1, p0, Lqf/b;->g:Ll2/b1;

    .line 22
    .line 23
    invoke-interface {p1}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    move-result-object p1

    .line 27
    check-cast p1, Luf/n;

    .line 28
    .line 29
    const/4 p2, 0x0

    .line 30
    iget-object p4, p0, Lqf/b;->e:Ljava/lang/String;

    .line 31
    .line 32
    iget-object p0, p0, Lqf/b;->f:Lyj/b;

    .line 33
    .line 34
    invoke-static {p4, p1, p0, p3, p2}, Lkp/c0;->a(Ljava/lang/String;Luf/n;Lyj/b;Ll2/o;I)V

    .line 35
    .line 36
    .line 37
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 38
    .line 39
    return-object p0

    .line 40
    :pswitch_0
    const-string v0, "$this$composable"

    .line 41
    .line 42
    const-string v1, "it"

    .line 43
    .line 44
    invoke-static {p4, p1, v0, p2, v1}, Lz9/c;->c(Ljava/lang/Integer;Lb1/n;Ljava/lang/String;Lz9/k;Ljava/lang/String;)V

    .line 45
    .line 46
    .line 47
    iget-object p1, p0, Lqf/b;->g:Ll2/b1;

    .line 48
    .line 49
    invoke-interface {p1}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 50
    .line 51
    .line 52
    move-result-object p1

    .line 53
    check-cast p1, Luf/p;

    .line 54
    .line 55
    invoke-static {p1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 56
    .line 57
    .line 58
    const/4 p2, 0x0

    .line 59
    iget-object p4, p0, Lqf/b;->e:Ljava/lang/String;

    .line 60
    .line 61
    iget-object p0, p0, Lqf/b;->f:Lyj/b;

    .line 62
    .line 63
    invoke-static {p1, p4, p0, p3, p2}, Lkp/y9;->a(Luf/p;Ljava/lang/String;Lyj/b;Ll2/o;I)V

    .line 64
    .line 65
    .line 66
    goto :goto_0

    .line 67
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
