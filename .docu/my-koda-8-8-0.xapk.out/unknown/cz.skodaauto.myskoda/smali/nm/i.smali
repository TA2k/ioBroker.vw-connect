.class public interface abstract Lnm/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lnm/e;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    sget-object v0, Lnm/h;->c:Lnm/h;

    .line 2
    .line 3
    new-instance v1, Lnm/e;

    .line 4
    .line 5
    invoke-direct {v1, v0}, Lnm/e;-><init>(Lnm/h;)V

    .line 6
    .line 7
    .line 8
    sput-object v1, Lnm/i;->a:Lnm/e;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public abstract h(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
.end method
