.class public final Lw20/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lw20/a;

.field public final b:Lkf0/h0;


# direct methods
.method public constructor <init>(Lw20/a;Lkf0/h0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lw20/e;->a:Lw20/a;

    .line 5
    .line 6
    iput-object p2, p0, Lw20/e;->b:Lkf0/h0;

    .line 7
    .line 8
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
    check-cast v1, Lss0/j0;

    .line 5
    .line 6
    iget-object v1, v1, Lss0/j0;->d:Ljava/lang/String;

    .line 7
    .line 8
    const-string v2, "$v$c$cz-skodaauto-myskoda-library-vehicle-model-Vin$-input$0"

    .line 9
    .line 10
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    iget-object v2, p0, Lw20/e;->b:Lkf0/h0;

    .line 14
    .line 15
    iget-object v2, v2, Lkf0/h0;->a:Lif0/t;

    .line 16
    .line 17
    iput-object v1, v2, Lif0/t;->a:Ljava/lang/String;

    .line 18
    .line 19
    iget-object p0, p0, Lw20/e;->a:Lw20/a;

    .line 20
    .line 21
    check-cast p0, Liy/b;

    .line 22
    .line 23
    sget-object v1, Lly/b;->q1:Lly/b;

    .line 24
    .line 25
    invoke-interface {p0, v1}, Ltl0/a;->a(Lul0/f;)V

    .line 26
    .line 27
    .line 28
    return-object v0
.end method
