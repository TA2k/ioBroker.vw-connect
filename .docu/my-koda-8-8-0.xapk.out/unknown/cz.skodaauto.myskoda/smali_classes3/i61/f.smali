.class public final synthetic Li61/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Z

.field public final synthetic f:Ljava/lang/Object;

.field public final synthetic g:Ljava/lang/Enum;

.field public final synthetic h:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;Ljava/lang/Enum;ZLjava/lang/Object;I)V
    .locals 0

    .line 1
    iput p5, p0, Li61/f;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Li61/f;->f:Ljava/lang/Object;

    .line 4
    .line 5
    iput-object p2, p0, Li61/f;->g:Ljava/lang/Enum;

    .line 6
    .line 7
    iput-boolean p3, p0, Li61/f;->e:Z

    .line 8
    .line 9
    iput-object p4, p0, Li61/f;->h:Ljava/lang/Object;

    .line 10
    .line 11
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 12
    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 3

    .line 1
    iget v0, p0, Li61/f;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Li61/f;->f:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Ltechnology/cariad/cat/genx/ClientCrossDelegate;

    .line 9
    .line 10
    iget-object v1, p0, Li61/f;->g:Ljava/lang/Enum;

    .line 11
    .line 12
    check-cast v1, Ltechnology/cariad/cat/genx/Channel;

    .line 13
    .line 14
    iget-object v2, p0, Li61/f;->h:Ljava/lang/Object;

    .line 15
    .line 16
    check-cast v2, Ljava/lang/String;

    .line 17
    .line 18
    iget-boolean p0, p0, Li61/f;->e:Z

    .line 19
    .line 20
    invoke-static {v0, v1, p0, v2}, Ltechnology/cariad/cat/genx/ClientCrossDelegate;->d(Ltechnology/cariad/cat/genx/ClientCrossDelegate;Ltechnology/cariad/cat/genx/Channel;ZLjava/lang/String;)I

    .line 21
    .line 22
    .line 23
    move-result p0

    .line 24
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    return-object p0

    .line 29
    :pswitch_0
    iget-object v0, p0, Li61/f;->f:Ljava/lang/Object;

    .line 30
    .line 31
    check-cast v0, Ltechnology/cariad/cat/genx/Car2PhoneMode;

    .line 32
    .line 33
    iget-object v1, p0, Li61/f;->g:Ljava/lang/Enum;

    .line 34
    .line 35
    check-cast v1, Lg61/h;

    .line 36
    .line 37
    iget-object v2, p0, Li61/f;->h:Ljava/lang/Object;

    .line 38
    .line 39
    check-cast v2, Lg61/p;

    .line 40
    .line 41
    iget-boolean p0, p0, Li61/f;->e:Z

    .line 42
    .line 43
    invoke-static {v0, v1, p0, v2}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;->l(Ltechnology/cariad/cat/genx/Car2PhoneMode;Lg61/h;ZLg61/p;)Ljava/lang/String;

    .line 44
    .line 45
    .line 46
    move-result-object p0

    .line 47
    return-object p0

    .line 48
    nop

    .line 49
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
