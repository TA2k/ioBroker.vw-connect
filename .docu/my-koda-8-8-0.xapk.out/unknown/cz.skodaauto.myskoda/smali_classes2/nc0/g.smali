.class public final Lnc0/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# static fields
.field public static final e:Lnc0/g;

.field public static final f:Lnc0/g;


# instance fields
.field public final synthetic d:I


# direct methods
.method static synthetic constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lnc0/g;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Lnc0/g;-><init>(I)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Lnc0/g;->e:Lnc0/g;

    .line 8
    .line 9
    new-instance v0, Lnc0/g;

    .line 10
    .line 11
    const/4 v1, 0x1

    .line 12
    invoke-direct {v0, v1}, Lnc0/g;-><init>(I)V

    .line 13
    .line 14
    .line 15
    sput-object v0, Lnc0/g;->f:Lnc0/g;

    .line 16
    .line 17
    return-void
.end method

.method public synthetic constructor <init>(I)V
    .locals 0

    .line 1
    iput p1, p0, Lnc0/g;->d:I

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    iget p0, p0, Lnc0/g;->d:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Llc0/a;

    .line 7
    .line 8
    iget-object p0, p1, Llc0/a;->a:Ljava/lang/String;

    .line 9
    .line 10
    const-string p1, "$v$c$cz-skodaauto-myskoda-library-authcomponent-model-AccessToken$-$this$mapData$0"

    .line 11
    .line 12
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    return-object p0

    .line 16
    :pswitch_0
    check-cast p1, Llc0/a;

    .line 17
    .line 18
    iget-object p0, p1, Llc0/a;->a:Ljava/lang/String;

    .line 19
    .line 20
    const-string p1, "$v$c$cz-skodaauto-myskoda-library-authcomponent-model-AccessToken$-$this$mapData$0"

    .line 21
    .line 22
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 23
    .line 24
    .line 25
    return-object p0

    .line 26
    nop

    .line 27
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
