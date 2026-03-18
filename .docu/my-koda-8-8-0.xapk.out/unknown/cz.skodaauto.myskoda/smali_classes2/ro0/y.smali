.class public final Lro0/y;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lro0/g;


# direct methods
.method public constructor <init>(Lro0/g;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lro0/y;->a:Lro0/g;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 3

    .line 1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 2
    .line 3
    move-object v1, v0

    .line 4
    check-cast v1, Lto0/h;

    .line 5
    .line 6
    iget-object v1, v1, Lto0/h;->a:Ljava/lang/String;

    .line 7
    .line 8
    const-string v2, "$v$c$cz-skodaauto-myskoda-library-powerpass-model-EvseId$-input$0"

    .line 9
    .line 10
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    iget-object p0, p0, Lro0/y;->a:Lro0/g;

    .line 14
    .line 15
    check-cast p0, Lpo0/j;

    .line 16
    .line 17
    iput-object v1, p0, Lpo0/j;->a:Ljava/lang/String;

    .line 18
    .line 19
    return-object v0
.end method
