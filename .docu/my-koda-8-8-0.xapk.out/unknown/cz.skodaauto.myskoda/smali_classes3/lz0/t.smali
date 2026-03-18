.class public final Llz0/t;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Llz0/m;


# instance fields
.field public final a:Li40/e1;


# direct methods
.method public constructor <init>(Li40/e1;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Llz0/t;->a:Li40/e1;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a(Llz0/c;Ljava/lang/CharSequence;I)Ljava/lang/Object;
    .locals 1

    .line 1
    const-string v0, "input"

    .line 2
    .line 3
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Llz0/t;->a:Li40/e1;

    .line 7
    .line 8
    invoke-virtual {p0, p1}, Li40/e1;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 9
    .line 10
    .line 11
    invoke-static {p3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0
.end method
