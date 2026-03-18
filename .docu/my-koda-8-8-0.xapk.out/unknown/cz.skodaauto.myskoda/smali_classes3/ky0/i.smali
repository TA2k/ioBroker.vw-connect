.class public final Lky0/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lky0/j;


# instance fields
.field public final synthetic a:I

.field public final b:Ljava/lang/Object;

.field public final c:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Lay0/a;Lay0/k;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Lky0/i;->a:I

    const-string v0, "getNextValue"

    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lky0/i;->c:Ljava/lang/Object;

    iput-object p2, p0, Lky0/i;->b:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Ljava/io/File;)V
    .locals 2

    const/4 v0, 0x2

    iput v0, p0, Lky0/i;->a:I

    sget-object v0, Lwx0/h;->d:Lwx0/h;

    const-string v1, "start"

    invoke-static {p1, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-object p1, p0, Lky0/i;->c:Ljava/lang/Object;

    .line 3
    iput-object v0, p0, Lky0/i;->b:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lky0/j;Lay0/k;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Lky0/i;->a:I

    const-string v0, "sequence"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "predicate"

    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 5
    iput-object p1, p0, Lky0/i;->c:Ljava/lang/Object;

    .line 6
    iput-object p2, p0, Lky0/i;->b:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final iterator()Ljava/util/Iterator;
    .locals 1

    .line 1
    iget v0, p0, Lky0/i;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Lwx0/f;

    .line 7
    .line 8
    invoke-direct {v0, p0}, Lwx0/f;-><init>(Lky0/i;)V

    .line 9
    .line 10
    .line 11
    return-object v0

    .line 12
    :pswitch_0
    new-instance v0, Lky0/f;

    .line 13
    .line 14
    invoke-direct {v0, p0}, Lky0/f;-><init>(Lky0/i;)V

    .line 15
    .line 16
    .line 17
    return-object v0

    .line 18
    :pswitch_1
    new-instance v0, Landroidx/collection/o0;

    .line 19
    .line 20
    invoke-direct {v0, p0}, Landroidx/collection/o0;-><init>(Lky0/i;)V

    .line 21
    .line 22
    .line 23
    return-object v0

    .line 24
    nop

    .line 25
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
