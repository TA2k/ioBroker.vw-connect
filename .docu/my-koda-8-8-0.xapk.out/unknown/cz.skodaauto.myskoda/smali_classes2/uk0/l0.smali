.class public final Luk0/l0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lro0/y;

.field public final b:Luk0/w;


# direct methods
.method public constructor <init>(Lro0/y;Luk0/w;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Luk0/l0;->a:Lro0/y;

    .line 5
    .line 6
    iput-object p2, p0, Luk0/l0;->b:Luk0/w;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/String;)V
    .locals 1

    .line 1
    const-string v0, "$v$c$cz-skodaauto-myskoda-library-powerpass-model-EvseId$-input$0"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Luk0/l0;->a:Lro0/y;

    .line 7
    .line 8
    iget-object v0, v0, Lro0/y;->a:Lro0/g;

    .line 9
    .line 10
    check-cast v0, Lpo0/j;

    .line 11
    .line 12
    iput-object p1, v0, Lpo0/j;->a:Ljava/lang/String;

    .line 13
    .line 14
    iget-object p0, p0, Luk0/l0;->b:Luk0/w;

    .line 15
    .line 16
    check-cast p0, Liy/b;

    .line 17
    .line 18
    sget-object p1, Lly/b;->a3:Lly/b;

    .line 19
    .line 20
    invoke-interface {p0, p1}, Ltl0/a;->a(Lul0/f;)V

    .line 21
    .line 22
    .line 23
    return-void
.end method

.method public final synthetic invoke()Ljava/lang/Object;
    .locals 2

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
    invoke-virtual {p0, v1}, Luk0/l0;->a(Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    return-object v0
.end method
