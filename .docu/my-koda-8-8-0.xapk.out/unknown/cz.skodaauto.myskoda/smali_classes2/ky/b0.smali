.class public final Lky/b0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lky/j;


# direct methods
.method public constructor <init>(Lky/j;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lky/b0;->a:Lky/j;

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
    check-cast v1, Lcz/skodaauto/myskoda/library/deeplink/model/Link;

    .line 5
    .line 6
    invoke-virtual {v1}, Lcz/skodaauto/myskoda/library/deeplink/model/Link;->unbox-impl()Ljava/lang/String;

    .line 7
    .line 8
    .line 9
    move-result-object v1

    .line 10
    const-string v2, "$v$c$cz-skodaauto-myskoda-library-deeplink-model-Link$-input$0"

    .line 11
    .line 12
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    const/4 v2, 0x1

    .line 16
    iget-object p0, p0, Lky/b0;->a:Lky/j;

    .line 17
    .line 18
    check-cast p0, Liy/b;

    .line 19
    .line 20
    invoke-virtual {p0, v1, v2, v2}, Liy/b;->c(Ljava/lang/String;ZZ)V

    .line 21
    .line 22
    .line 23
    return-object v0
.end method
