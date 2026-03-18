.class public final Li20/t;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lkf0/f;

.field public final b:Li20/i;


# direct methods
.method public constructor <init>(Lkf0/f;Li20/i;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Li20/t;->a:Lkf0/f;

    .line 5
    .line 6
    iput-object p2, p0, Li20/t;->b:Li20/i;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 5

    .line 1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 2
    .line 3
    check-cast v0, Lss0/j0;

    .line 4
    .line 5
    iget-object v0, v0, Lss0/j0;->d:Ljava/lang/String;

    .line 6
    .line 7
    const-string v1, "$v$c$cz-skodaauto-myskoda-library-vehicle-model-Vin$-input$0"

    .line 8
    .line 9
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    iget-object v1, p0, Li20/t;->a:Lkf0/f;

    .line 13
    .line 14
    invoke-virtual {v1, v0}, Lkf0/f;->a(Ljava/lang/String;)Lyy0/i;

    .line 15
    .line 16
    .line 17
    move-result-object v1

    .line 18
    new-instance v2, Laa/s;

    .line 19
    .line 20
    const/4 v3, 0x0

    .line 21
    const/16 v4, 0x9

    .line 22
    .line 23
    invoke-direct {v2, v4, p0, v0, v3}, Laa/s;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 24
    .line 25
    .line 26
    new-instance p0, Lne0/n;

    .line 27
    .line 28
    const/4 v0, 0x5

    .line 29
    invoke-direct {p0, v1, v2, v0}, Lne0/n;-><init>(Lyy0/i;Lay0/n;I)V

    .line 30
    .line 31
    .line 32
    return-object p0
.end method
