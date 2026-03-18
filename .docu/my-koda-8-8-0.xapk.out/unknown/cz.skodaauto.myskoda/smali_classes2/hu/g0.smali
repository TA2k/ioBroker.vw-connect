.class public final Lhu/g0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lju/b;
.implements Ltn/b;


# instance fields
.field public final synthetic d:I

.field public final e:Lkx0/a;


# direct methods
.method public synthetic constructor <init>(Lkx0/a;I)V
    .locals 0

    .line 1
    iput p2, p0, Lhu/g0;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lhu/g0;->e:Lkx0/a;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final get()Ljava/lang/Object;
    .locals 3

    .line 1
    iget v0, p0, Lhu/g0;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lhu/g0;->e:Lkx0/a;

    .line 7
    .line 8
    invoke-interface {p0}, Lkx0/a;->get()Ljava/lang/Object;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    check-cast p0, Landroid/content/Context;

    .line 13
    .line 14
    sget v0, Lyn/k;->g:I

    .line 15
    .line 16
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    invoke-virtual {v0}, Ljava/lang/Integer;->intValue()I

    .line 21
    .line 22
    .line 23
    move-result v0

    .line 24
    new-instance v1, Lyn/k;

    .line 25
    .line 26
    const-string v2, "com.google.android.datatransport.events"

    .line 27
    .line 28
    invoke-direct {v1, p0, v2, v0}, Lyn/k;-><init>(Landroid/content/Context;Ljava/lang/String;I)V

    .line 29
    .line 30
    .line 31
    return-object v1

    .line 32
    :pswitch_0
    iget-object p0, p0, Lhu/g0;->e:Lkx0/a;

    .line 33
    .line 34
    invoke-interface {p0}, Lkx0/a;->get()Ljava/lang/Object;

    .line 35
    .line 36
    .line 37
    move-result-object p0

    .line 38
    check-cast p0, Lhu/p0;

    .line 39
    .line 40
    new-instance v0, Lhu/f0;

    .line 41
    .line 42
    invoke-direct {v0, p0}, Lhu/f0;-><init>(Lhu/p0;)V

    .line 43
    .line 44
    .line 45
    return-object v0

    .line 46
    nop

    .line 47
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
