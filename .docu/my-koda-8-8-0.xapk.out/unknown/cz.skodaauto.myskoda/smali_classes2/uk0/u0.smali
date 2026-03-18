.class public final Luk0/u0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Luk0/e;


# direct methods
.method public constructor <init>(Luk0/e;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Luk0/u0;->a:Luk0/e;

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
    iget-object p0, p0, Luk0/u0;->a:Luk0/e;

    .line 14
    .line 15
    check-cast p0, Lsk0/a;

    .line 16
    .line 17
    iget-object p0, p0, Lsk0/a;->a:Lyy0/c2;

    .line 18
    .line 19
    new-instance v2, Lto0/h;

    .line 20
    .line 21
    invoke-direct {v2, v1}, Lto0/h;-><init>(Ljava/lang/String;)V

    .line 22
    .line 23
    .line 24
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 25
    .line 26
    .line 27
    const/4 v1, 0x0

    .line 28
    invoke-virtual {p0, v1, v2}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    return-object v0
.end method
